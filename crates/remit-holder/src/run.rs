//! Execution: read plane → (compute plane) → emit plane → receipt.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use remit_analyze::{bucket, bucket_ms};
use remit_kernel::{
    encode_params, ByteBuf, HostTable, KernelJob, KernelLimits, ReadErr, ReadHost, Status,
};
use remit_policy::{Actual, Privacy};
use remit_read::{arrowconv, Principal, ReadLimits, ReadPlane, ScanCounter};
use remit_receipt::{meet, Charged, Receipt, Runtime};
use remit_types::status_bits;
use remit_wire::{Mode, ParamType, ReadTemplate};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::admission::{Admitted, Stage};
use crate::state::{CachedResult, EngineHandle, Holder};

#[derive(Debug, Clone, Serialize)]
pub struct RunResponse {
    pub run_id: String,
    pub status: String,
    pub result: Option<Value>,
    pub labels: Vec<String>,
    pub terms: remit_receipt::Terms,
    pub provenance: Value,
    pub receipt: remit_wire::Envelope,
    pub usage: BTreeMap<String, String>,
    pub cached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<Stage>,
}

pub fn new_run_id() -> String {
    format!(
        "run_{:016x}{:08x}",
        rand::random::<u64>(),
        rand::random::<u32>()
    )
}

/// The Holder side of the kernel `data` interface over the read plane.
pub struct HolderReads {
    pub plane: Arc<ReadPlane>,
    pub principal: Principal,
    pub reads: BTreeMap<String, ReadTemplate>,
    pub calls: BTreeMap<String, u32>,
    pub counter: Arc<ScanCounter>,
    pub limits: ReadLimits,
    /// DP parameters *per read call* over DP-governed resources.
    pub dp: Option<remit_emit::dp::DpParams>,
    pub dp_reads: std::collections::BTreeSet<String>,
    /// Output layout of DP reads (column, kind).
    pub dp_layout: BTreeMap<String, Vec<(String, String)>>,
    /// Holder functions (`embed`, `geocode`, …): pure, priced, trusted plane.
    pub functions: Arc<crate::functions::Functions>,
    pub allowed_fns: std::collections::BTreeSet<String>,
}

#[async_trait::async_trait]
impl ReadHost for HolderReads {
    fn declared(&self) -> Vec<String> {
        self.reads.keys().cloned().collect()
    }
    async fn call(&mut self, name: &str, params: Map<String, Value>) -> Result<HostTable, ReadErr> {
        let t = self.reads.get(name).ok_or(ReadErr::Denied)?.clone();
        let n = self.calls.entry(name.to_string()).or_default();
        *n += 1;
        if *n > t.max_calls {
            return Err(ReadErr::CallCap);
        }
        // Only declared params are passed; their types come from the template.
        let mut p = Map::new();
        for (k, ty) in &t.params {
            let v = params.get(k).cloned().ok_or(ReadErr::ParamType)?;
            if arrowconv::param_scalar(&v, *ty).is_none() {
                return Err(ReadErr::ParamType);
            }
            p.insert(k.clone(), v);
        }
        let lim = ReadLimits {
            max_rows: t.max_rows,
            ..self.limits.clone()
        };
        let map_err = |e: remit_read::ReadError| match e {
            remit_read::ReadError::RowCap => ReadErr::RowCap,
            e if e.is_limit() => ReadErr::RowCap,
            remit_read::ReadError::Param(_) => ReadErr::ParamType,
            remit_read::ReadError::AggregateOnly(_) | remit_read::ReadError::Dp(_) => {
                ReadErr::Denied
            }
            _ => ReadErr::Internal,
        };
        if self.dp_reads.contains(name) {
            // DP is closed under post-processing: the kernel only ever sees
            // the noisy answer.
            let p_dp = self.dp.ok_or(ReadErr::Denied)?;
            let (shape, raw) = self
                .plane
                .execute_dp(
                    &t.sql,
                    &self.principal,
                    &p,
                    &t.params,
                    &lim,
                    self.counter.clone(),
                )
                .await
                .map_err(map_err)?;
            let (rows, _) =
                remit_emit::dp::release(&shape, &raw, p_dp).map_err(|_| ReadErr::Internal)?;
            if rows.len() as u64 > t.max_rows {
                return Err(ReadErr::RowCap);
            }
            let b = arrowconv::rows_to_batch(
                &rows,
                self.dp_layout.get(name).map(Vec::as_slice).unwrap_or(&[]),
            );
            return Ok(HostTable {
                schema_ipc: arrowconv::ipc_schema_message(&b.schema()),
                batches_ipc: if b.num_rows() > 0 {
                    vec![ByteBuf(arrowconv::ipc_batch_message(&b))]
                } else {
                    vec![]
                },
                rows: b.num_rows() as u64,
                bytes: b.get_array_memory_size() as u64,
            });
        }
        let out = self
            .plane
            .execute(
                &t.sql,
                &self.principal,
                &p,
                &t.params,
                &lim,
                self.counter.clone(),
            )
            .await
            .map_err(map_err)?;
        let bytes: u64 = out
            .batches
            .iter()
            .map(|b| b.get_array_memory_size() as u64)
            .sum();
        Ok(HostTable {
            schema_ipc: arrowconv::ipc_schema_message(&out.schema),
            batches_ipc: out
                .batches
                .iter()
                .filter(|b| b.num_rows() > 0)
                .map(|b| ByteBuf(arrowconv::ipc_batch_message(b)))
                .collect(),
            rows: out.rows,
            bytes,
        })
    }
    async fn holder_fn(&mut self, name: &str, args: Value) -> Result<Value, ReadErr> {
        if !self.allowed_fns.contains(name) {
            return Err(ReadErr::Denied);
        }
        self.functions.call(name, args).await
    }
    fn fn_prices(&self) -> BTreeMap<String, u64> {
        self.allowed_fns
            .iter()
            .filter_map(|n| Some((n.clone(), self.functions.price(n)?)))
            .collect()
    }
    fn fn_price(&self, name: &str) -> Option<u64> {
        self.functions.price(name)
    }
}

/// Run an admitted remit on its own task (a client disconnect never leaks a
/// reservation) behind the fair scheduler. `None`: the queue is full; nothing
/// ran and the reservation was released.
pub async fn run_admitted(h: &Arc<Holder>, a: Admitted, run_id: String) -> Option<RunResponse> {
    let h2 = h.clone();
    let slot = match h
        .sched
        .enqueue(&a.principal.id, a.weight, a.analysis.limits.fuel as f64)
    {
        Ok(s) => s,
        Err(_) => {
            release(h, &a).await;
            return None;
        }
    };
    let (reservation, fuel) = (a.reservation.clone(), a.analysis.limits.fuel);
    let receipt_for = (a.manifest.remit_id(), a.manifest.sender.clone());
    let rid = run_id.clone();
    let task = tokio::spawn(async move {
        let _permit = slot.wait().await;
        execute(&h2, a, rid).await
    });
    let h3 = h.clone();
    // The supervisor settles even if execution panics.
    let sup = tokio::spawn(async move {
        match task.await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("execution task failed: {e}");
                if let Some(r) = &reservation {
                    h3.ledger
                        .settle(r, Actual::used(fuel, r.ask.bits, r.ask.privacy))
                        .await;
                }
                failed_response(&h3, run_id, &receipt_for.0, &receipt_for.1)
            }
        }
    });
    sup.await.ok()
}

/// Give everything back for a remit that was admitted but never ran.
pub async fn release(h: &Holder, a: &Admitted) {
    h.nonces.forget(&a.manifest.sender, &a.manifest.nonce);
    if let Some(r) = &a.reservation {
        h.ledger.settle(r, Actual::default()).await;
    }
}

/// Start a run in the background and record it under `run_id`.
pub fn spawn_async(h: &Arc<Holder>, a: Admitted, run_id: String) {
    h.runs.lock().put(&run_id, "running", None, h.now_ms());
    let h = h.clone();
    tokio::spawn(async move {
        let v = match run_admitted(&h, a, run_id.clone()).await {
            Some(r) => serde_json::to_value(&r).unwrap_or(Value::Null),
            None => {
                json!({"run_id": run_id, "status": "limit_exceeded", "result": null, "message": "execution queue is full"})
            }
        };
        h.runs.lock().put(&run_id, "done", Some(v), h.now_ms());
    });
}

fn failed_response(h: &Holder, run_id: String, remit_id: &str, sender: &str) -> RunResponse {
    let r = Receipt {
        run_id: run_id.clone(),
        remit_id: remit_id.into(),
        sender: sender.into(),
        holder: h.id().into(),
        decision: "admitted".into(),
        policy_sha256: format!("sha256:{}", h.policy.policy_sha256()),
        status: "internal".into(),
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        runtime: Runtime {
            remit: env!("CARGO_PKG_VERSION").into(),
            wasmtime: remit_kernel::wasmtime_version().into(),
            engine: None,
            isolation: h.cfg.holder.isolation.clone(),
        },
        ..Default::default()
    };
    let env = r.sign(&h.signer);
    let _ = h.receipts.append(&run_id, &env);
    RunResponse {
        run_id,
        status: "internal".into(),
        result: None,
        labels: vec![],
        terms: Default::default(),
        provenance: json!({"holder": h.id(), "remit_id": remit_id}),
        receipt: env,
        usage: BTreeMap::new(),
        cached: false,
        log: None,
        trace: vec![],
    }
}

/// Key of a released answer: program, params, policy, data versions, scope.
pub fn result_cache_key(
    h: &Holder,
    plane: &ReadPlane,
    m: &remit_wire::Manifest,
    p: &remit_policy::PrincipalInfo,
    facts: &remit_analyze::Facts,
) -> String {
    let owner_scoped = facts
        .resources
        .keys()
        .any(|t| h.resources.get(t).is_some_and(|r| r.owner_column.is_some()));
    let who = if owner_scoped {
        p.id.clone()
    } else {
        String::new()
    };
    let mut g = p.groups.clone();
    g.sort();
    // The nonce is deliberately not part of the key: a fresh nonce must not buy
    // a fresh DP noise draw for the same program, params and snapshot.
    format!(
        "{}|{}|{}|{}|{}|{}",
        m.remit_id(),
        m.params_sha256(),
        h.policy.policy_sha256(),
        serde_json::to_string(&versions(plane, facts)).unwrap_or_default(),
        g.join(","),
        who
    )
}

fn versions(plane: &ReadPlane, facts: &remit_analyze::Facts) -> BTreeMap<String, String> {
    facts
        .resources
        .keys()
        .filter_map(|t| Some((t.clone(), plane.data_version(t)?)))
        .collect()
}

/// Execute an admitted remit and produce the signed response.
pub async fn execute(h: &Holder, a: Admitted, run_id: String) -> RunResponse {
    let t0 = Instant::now();
    let exec_start_ns = crate::otel::now_ns();
    let m = &a.manifest;
    let rt = a
        .analysis
        .rt
        .clone()
        .expect("bound type for runnable remit");
    let lim = &a.analysis.limits;
    let params = m.params.clone().unwrap_or_default();
    let principal = Principal {
        id: a.principal.id.clone(),
        groups: a.principal.groups.clone(),
    };
    // One snapshot for the whole run: versions, reads and receipt agree.
    let plane = a.plane.clone();
    let versions = versions(&plane, &a.analysis.facts);
    let ckey = a.cache_key.clone();
    let cached = a.cached.clone();
    let from_cache = cached.is_some();
    let execution = cached
        .as_ref()
        .and_then(|c| c.execution.clone())
        .or_else(|| {
            (m.mode == Mode::Kernel).then(|| remit_receipt::ExecutionContext {
                issued_at: m.issued_at.clone(),
                nonce: m.nonce.clone(),
            })
        });
    // A cached answer is free only for principals that already received it.
    let paid_before = cached
        .as_ref()
        .is_some_and(|c| c.seen_by.contains(&a.principal.id));
    let read_limits = ReadLimits {
        max_rows: 0,
        scan_rows: lim.scan_rows,
        scan_bytes: lim.scan_bytes,
        memory_bytes: lim.memory_bytes,
        timeout: Duration::from_millis(lim.wall_ms),
    };
    let mut fuel_used = 0u64;
    let mut log = String::new();
    let mut spent = Privacy::ZERO;
    let (status, value, result_sha) = if let Some(c) = cached {
        h.metrics
            .result_cache_hits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ("ok".to_string(), Some(c.value), Some(c.result_sha256))
    } else {
        let produced: Result<Value, String> = match m.mode {
            Mode::Query => {
                let (_, r) = m.reads.iter().next().expect("one root read");
                let counter = ScanCounter::new(lim.scan_rows, lim.scan_bytes);
                let rl = ReadLimits {
                    max_rows: r.max_rows,
                    ..read_limits.clone()
                };
                let produced = match &a.dp {
                    Some(dp) => match plane
                        .execute_dp(&r.sql, &principal, &params, &r.params, &rl, counter)
                        .await
                    {
                        Ok((shape, raw)) => match remit_emit::dp::release(&shape, &raw, *dp) {
                            Ok((rows, _)) if rows.len() as u64 > r.max_rows => {
                                spent = crate::admission::privacy_of(dp);
                                Err(remit_read::ReadError::RowCap)
                            }
                            Ok((rows, _)) => {
                                spent = crate::admission::privacy_of(dp);
                                // Noise may leave the declared bounds: clamping
                                // a DP answer is free post-processing.
                                Ok(rows
                                    .into_iter()
                                    .map(|r| remit_emit::clamp_row(&rt, r))
                                    .collect())
                            }
                            Err(e) => Err(remit_read::ReadError::Internal(e.to_string())),
                        },
                        Err(e) => Err(e),
                    },
                    None => plane
                        .execute(&r.sql, &principal, &params, &r.params, &rl, counter)
                        .await
                        .map(|out| arrowconv::batches_to_rows(&out.batches)),
                };
                match produced {
                    Ok(rows) => Ok(remit_emit::shape_rows(&rt, rows)),
                    Err(e) if e.is_limit() => Err("limit_exceeded".into()),
                    Err(e) => {
                        log.push_str(&e.to_string());
                        Err("internal".into())
                    }
                }
            }
            Mode::Kernel => {
                let reads = HolderReads {
                    plane: plane.clone(),
                    principal: principal.clone(),
                    reads: m.reads.clone(),
                    calls: BTreeMap::new(),
                    counter: ScanCounter::new(lim.scan_rows, lim.scan_bytes),
                    limits: read_limits.clone(),
                    dp: a.dp.map(|d| {
                        // Sequential composition over every DP read call.
                        let calls: u32 = a
                            .analysis
                            .dp
                            .keys()
                            .filter_map(|n| m.reads.get(n))
                            .map(|r| r.max_calls)
                            .sum();
                        remit_emit::dp::DpParams {
                            epsilon: d.epsilon / calls.max(1) as f64,
                            delta: d.delta / calls.max(1) as f64,
                            ..d
                        }
                    }),
                    dp_reads: a.analysis.dp.keys().cloned().collect(),
                    dp_layout: a
                        .analysis
                        .dp
                        .iter()
                        .filter_map(|(n, s)| {
                            let out = &a.analysis.plans.get(n)?.output;
                            // AVG is always fractional; everything else keeps its SQL kind.
                            Some((
                                n.clone(),
                                s.columns
                                    .iter()
                                    .map(|(c, k)| {
                                        (
                                            c.clone(),
                                            if matches!(k, remit_read::DpOut::Avg { .. }) {
                                                "float".into()
                                            } else {
                                                out.iter()
                                                    .find(|(o, _)| o == c)
                                                    .map(|(_, k)| k.clone())
                                                    .unwrap_or_else(|| "string".into())
                                            },
                                        )
                                    })
                                    .collect(),
                            ))
                        })
                        .collect(),
                    functions: h.functions.clone(),
                    allowed_fns: h.functions.visible(&a.principal.groups),
                };
                if let Some(dp) = &a.dp {
                    spent = crate::admission::privacy_of(dp);
                }
                let ts_keys: Vec<String> = m
                    .param_types()
                    .into_iter()
                    .filter(|(_, t)| *t == ParamType::Timestamp)
                    .map(|(k, _)| k)
                    .collect();
                let job = KernelJob {
                    source: a.source.clone().unwrap_or_default(),
                    entry: m
                        .code
                        .as_ref()
                        .map(|c| c.entry.clone())
                        .unwrap_or_else(|| "main".into()),
                    params_cbor: encode_params(&params, &ts_keys),
                    nonce: m.nonce.clone(),
                    issued_at_ms: m.issued_at_ms(),
                    limits: KernelLimits {
                        fuel: lim.fuel,
                        memory_bytes: lim.memory_bytes,
                        wall_ms: lim.wall_ms,
                    },
                    component: m.code.as_ref().is_some_and(|c| c.lang == "wasm/component"),
                    compiled: None,
                };
                let lang = m
                    .code
                    .as_ref()
                    .map(|c| c.lang.as_str())
                    .unwrap_or("js/es2023");
                let outcome = match h.engine(lang) {
                    Some(EngineHandle::InProcess(e)) => e.run(&job, Box::new(reads)).await,
                    Some(EngineHandle::Process { pool, .. }) => {
                        pool.run(&a.trust_domain, &job, Box::new(reads)).await
                    }
                    None => unreachable!("rejected at admission"),
                };
                fuel_used = outcome.fuel_used + outcome.host_fuel;
                log.push_str(&outcome.log);
                match outcome.status {
                    Status::Ok => remit_emit::decode_kernel(&outcome.result_cbor)
                        .map_err(|_| "type_violation".to_string()),
                    s => Err(s.as_str().to_string()),
                }
            }
        };
        match produced {
            Ok(v) => match remit_emit::emit(&rt, &v, lim.output_bytes) {
                Ok(e) => {
                    h.result_cache.lock().put(
                        ckey.clone(),
                        CachedResult {
                            value: e.value.clone(),
                            result_sha256: e.result_sha256.clone(),
                            execution: execution.clone(),
                            seen_by: std::iter::once(a.principal.id.clone()).collect(),
                        },
                    );
                    ("ok".to_string(), Some(e.value), Some(e.result_sha256))
                }
                Err(err) => {
                    log.push_str(&format!("\n{err}"));
                    (err.status().to_string(), None, None)
                }
            },
            Err(s) => (s, None, None),
        }
    };
    // Timing padding to fixed latency classes for sensitive resources.
    let pad = a
        .analysis
        .facts
        .resources
        .keys()
        .filter_map(|t| h.resources.get(t).and_then(|r| r.pad_ms))
        .max();
    if let Some(p) = pad {
        let el = t0.elapsed();
        let class = Duration::from_millis(p);
        let target = class * ((el.as_millis() as u32 / p.max(1) as u32) + 1);
        tokio::time::sleep(target.saturating_sub(el)).await;
    }
    // Charges: a value reveals up to its capacity; a failure reveals only the
    // status. A cached answer reveals nothing new globally, but a principal
    // that has not seen it yet pays for the bits (and ε) it receives.
    let cache_hit = from_cache;
    let full = if status == "ok" {
        a.analysis.facts.result_bits
    } else {
        status_bits() as u64
    };
    let mut actual = if cache_hit {
        let (bits, privacy) = if paid_before {
            (0, Privacy::ZERO)
        } else {
            (
                full,
                a.dp.map(|d| crate::admission::privacy_of(&d))
                    .unwrap_or(Privacy::ZERO),
            )
        };
        if let Some(c) = h.result_cache.lock().get_mut(&ckey) {
            c.seen_by.insert(a.principal.id.clone());
        }
        Actual {
            fuel: 0,
            bits,
            global_bits: 0,
            privacy,
            global_privacy: Privacy::ZERO,
        }
    } else {
        Actual::used(fuel_used.min(lim.fuel), full, spent)
    };
    let bits_charged = actual.bits;
    let eps_charged = if actual.privacy.is_zero() {
        0.0
    } else {
        lim.epsilon
    };
    // Labels and terms: the meet of the inputs.
    let inputs: Vec<(Vec<String>, Option<u64>, Option<bool>)> = a
        .analysis
        .facts
        .resources
        .keys()
        .filter_map(|t| h.resources.get(t))
        .map(|r| (r.labels.clone(), r.retain_days, r.forward))
        .collect();
    let (labels, terms) = meet(inputs.iter().map(|(l, r, f)| (l.as_slice(), *r, *f)));
    let mut usage = BTreeMap::new();
    usage.insert("fuel".to_string(), bucket(fuel_used));
    usage.insert(
        "wall".to_string(),
        bucket_ms(t0.elapsed().as_micros() as u64),
    );
    let (_, catalog_sha) = h.catalog(&a.principal.groups);
    let mut receipt = Receipt {
        run_id: run_id.clone(),
        remit_id: m.remit_id(),
        params_sha256: m.params_sha256(),
        sender: m.sender.clone(),
        holder: h.id().to_string(),
        decision: "admitted".into(),
        policy_sha256: format!("sha256:{}", h.policy.policy_sha256()),
        catalog_sha256: catalog_sha,
        data_versions: versions,
        result_sha256: result_sha,
        result_bits_max: a.analysis.facts.result_bits,
        status: status.clone(),
        labels: labels.clone(),
        terms: terms.clone(),
        usage: usage.clone(),
        charged: Charged {
            bits: bits_charged,
            epsilon: eps_charged,
        },
        runtime: Runtime {
            remit: env!("CARGO_PKG_VERSION").into(),
            wasmtime: remit_kernel::wasmtime_version().into(),
            engine: if m.mode == Mode::Kernel {
                m.code.as_ref().and_then(|c| h.engine_id(&c.lang))
            } else {
                None
            },
            isolation: h.cfg.holder.isolation.clone(),
        },
        cached: cache_hit,
        execution,
        attestation: None,
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    };
    let mut value = value;
    let mut status = status;
    if let Some(at) = &h.cfg.holder.attestation {
        let (mut r, fmt, cmd) = (receipt.clone(), at.format.clone(), at.command.clone());
        let done = tokio::task::spawn_blocking(move || {
            remit_receipt::attest::attach(
                &mut r,
                &remit_receipt::attest::CommandAttester {
                    format: fmt,
                    command: cmd,
                },
            )
            .map(|()| r)
        })
        .await;
        match done {
            Ok(Ok(r)) => receipt = r,
            e => {
                tracing::error!("attestation failed: {e:?}");
                if at.required {
                    // No evidence, no answer.
                    value = None;
                    status = "internal".into();
                    receipt.status = status.clone();
                    receipt.result_sha256 = None;
                }
            }
        }
    }
    let mut env = receipt.sign(&h.signer);
    if let Some(ep) = &h.cfg.holder.otlp_endpoint {
        crate::otel::export(
            ep,
            crate::otel::trace_request(
                h.id(),
                &receipt.remit_id,
                &status,
                &a.trace,
                exec_start_ns,
                crate::otel::now_ns(),
            ),
        );
    }
    if let Err(e) = h.receipts.append(&run_id, &env) {
        tracing::error!("receipt log: {e}");
        h.result_cache.lock().pop(&ckey);
        status = "internal".into();
        value = None;
        receipt.status = status.clone();
        receipt.result_sha256 = None;
        receipt.attestation = None;
        actual = Actual::used(fuel_used.min(lim.fuel), status_bits() as u64, spent);
        receipt.charged.bits = actual.bits;
        receipt.charged.epsilon = if actual.privacy.is_zero() {
            0.0
        } else {
            lim.epsilon
        };
        env = receipt.sign(&h.signer);
    }
    if let Some(r) = &a.reservation {
        h.ledger.settle(r, actual).await;
    }
    if status == "ok" {
        h.metrics
            .runs_ok
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        h.metrics
            .runs_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(run_id, status, log = %log.trim(), "remit failed");
    }
    RunResponse {
        run_id,
        status,
        result: value,
        labels,
        terms,
        provenance: json!({"holder": h.id(), "remit_id": m.remit_id(), "params_sha256": m.params_sha256()}),
        receipt: env,
        usage,
        cached: cache_hit,
        log: if h.cfg.holder.dev && !log.trim().is_empty() {
            Some(log.trim().to_string())
        } else {
            None
        },
        trace: if h.cfg.holder.explain {
            a.trace.clone()
        } else {
            vec![]
        },
    }
}

/// Receipt for a terminal *admission* state (rejected / pending / counter-offer).
pub fn admission_receipt(
    h: &Holder,
    remit_id: &str,
    sender: &str,
    decision: &str,
) -> remit_wire::Envelope {
    let run_id = new_run_id();
    let r = Receipt {
        run_id: run_id.clone(),
        remit_id: remit_id.into(),
        sender: sender.into(),
        holder: h.id().into(),
        decision: decision.into(),
        policy_sha256: format!("sha256:{}", h.policy.policy_sha256()),
        status: "denied".into(),
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        runtime: Runtime {
            remit: env!("CARGO_PKG_VERSION").into(),
            wasmtime: remit_kernel::wasmtime_version().into(),
            engine: None,
            isolation: h.cfg.holder.isolation.clone(),
        },
        ..Default::default()
    };
    let env = r.sign(&h.signer);
    let _ = h.receipts.append(&run_id, &env);
    env
}

/// Replay audit: determinism means a recorded remit can be re-run at the same
/// data versions and must reproduce `result_sha256`. DP answers are random by
/// design and cannot be replayed.
pub async fn replay(
    h: &Arc<Holder>,
    mut m: remit_wire::Manifest,
    rc: &Receipt,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        rc.remit_id == m.remit_id() && rc.params_sha256 == m.params_sha256(),
        "the envelope is not the one this receipt records"
    );
    anyhow::ensure!(
        rc.status == "ok",
        "only successful runs can be replayed (recorded status: {})",
        rc.status
    );
    if let Some(context) = &rc.execution {
        m.issued_at = context.issued_at.clone();
        m.nonce = context.nonce.clone();
    }
    let source = crate::admission::resolve_source(h, &m)?;
    if let (Some(code), Some(source)) = (m.code.as_mut(), source.as_ref()) {
        code.source = Some(source.clone());
    }
    let (principal, domain) = h.principal(&m.sender, &Default::default());
    let rp = Principal {
        id: principal.id.clone(),
        groups: principal.groups.clone(),
    };
    let plane = h.plane();
    let analysis = remit_analyze::analyze(&m, &plane, &rp, &h.cfg.runtime.limits)
        .await
        .map_err(|d| {
            anyhow::anyhow!(
                "analysis: {}",
                serde_json::to_string(&d).unwrap_or_default()
            )
        })?;
    anyhow::ensure!(
        analysis.dp.is_empty(),
        "differentially private answers are randomized and cannot be replayed"
    );
    for (t, v) in &rc.data_versions {
        anyhow::ensure!(
            plane.data_version(t).as_ref() == Some(v),
            "`{t}` is at {:?}, the receipt recorded {v}: restore that snapshot first",
            plane.data_version(t)
        );
    }
    let want_engine = rc.runtime.engine.clone();
    let facts = analysis.facts.clone();
    let a = Admitted {
        decision: h.policy.decide(&principal, &facts),
        cache_key: result_cache_key(h, &plane, &m, &principal, &facts),
        source,
        weight: 1,
        cached: None,
        plane,
        principal,
        trust_domain: domain,
        analysis: Arc::new(analysis),
        reservation: None,
        datasets: vec![],
        trace: vec![],
        dp: None,
        plan_cache_hit: false,
        manifest: m,
    };
    anyhow::ensure!(a.decision.allowed, "policy no longer permits this remit");
    let r = execute(h, a, new_run_id()).await;
    let env: Receipt = serde_json::from_slice(
        &r.receipt
            .payload_bytes()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    )?;
    anyhow::ensure!(
        env.runtime.engine == want_engine,
        "engine differs: recorded {want_engine:?}, now {:?}",
        env.runtime.engine
    );
    anyhow::ensure!(
        env.result_sha256 == rc.result_sha256,
        "MISMATCH: recorded {:?}, replayed {:?}",
        rc.result_sha256,
        env.result_sha256
    );
    Ok(format!(
        "replay ok: {} reproduced {}",
        rc.run_id,
        rc.result_sha256.clone().unwrap_or_default()
    ))
}
