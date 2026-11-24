//! `remit`: the Remit command-line tool.

mod bench;
mod codegen;
mod conformance;
mod dev;
mod sender;

use std::path::PathBuf;

use anyhow::{anyhow, Context as _};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(
    name = "remit",
    version,
    about = "Remit: agents exchange programs, not messages"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a Holder from remit.toml.
    Serve {
        #[arg(short, long, default_value = "remit.toml")]
        config: PathBuf,
        /// Override `holder.listen`.
        #[arg(long)]
        listen: Option<String>,
    },
    /// Internal: kernel worker process (isolation = "process").
    #[command(hide = true)]
    KernelWorker {
        #[arg(long)]
        engine: PathBuf,
        #[arg(long)]
        sha256: Option<String>,
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long, default_value = "js/es2023")]
        lang: String,
        #[arg(long, default_value_t = 256 << 20)]
        max_memory_bytes: u64,
    },
    /// Internal: harden like a kernel worker, then try to escape.
    #[command(hide = true)]
    WorkerSelftest { secret_file: PathBuf },
    /// Internal: compile one Sender-built component under resource limits.
    #[command(hide = true)]
    CompileWorker {
        #[arg(long, default_value_t = 256 << 20)]
        max_memory_bytes: u64,
    },
    /// Generate an identity (did:key, or a did:web id with --id).
    Keygen {
        /// P-256 (ES256) instead of Ed25519.
        #[arg(long)]
        p256: bool,
        #[arg(long)]
        id: Option<String>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Fill defaults and sign a manifest into a DSSE envelope.
    Sign {
        manifest: PathBuf,
        #[arg(long, env = "REMIT_IDENTITY")]
        identity: PathBuf,
        /// Holder id (`did:web:…`) if the manifest does not name one.
        #[arg(long)]
        holder_id: Option<String>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Admission only: decision, diagnostics, counter-offers, cost.
    Check {
        file: PathBuf,
        #[arg(long)]
        holder: String,
        #[arg(long, env = "REMIT_IDENTITY")]
        identity: Option<PathBuf>,
    },
    /// Show the access card, capacity and admission trace.
    Explain {
        file: PathBuf,
        #[arg(long)]
        holder: String,
        #[arg(long, env = "REMIT_IDENTITY")]
        identity: Option<PathBuf>,
    },
    /// Submit and execute.
    Run {
        file: PathBuf,
        #[arg(long)]
        holder: String,
        #[arg(long, env = "REMIT_IDENTITY")]
        identity: Option<PathBuf>,
        /// Auto-accept counter-offers (re-sign with the Holder's clamps).
        #[arg(long)]
        accept_counter_offers: bool,
    },
    /// Offline verification with the same verifier the Holder runs (no data).
    Lint { manifest: PathBuf },
    /// Fetch a catalog and generate `.remit/<name>/{catalog.json,types.d.ts,schema.sql,stats.json,examples/}`.
    Pull {
        holder: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = ".remit")]
        dir: PathBuf,
    },
    /// Local Holder emulator seeded with synthetic data from a pulled catalog.
    Dev {
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        #[arg(long, default_value = "engines/js/dist/remit_engine_js.wasm")]
        engine: PathBuf,
        #[arg(long, default_value_t = 200)]
        rows: usize,
    },
    /// Black-box conformance suite against any Holder.
    Conformance {
        holder: String,
        #[arg(long, env = "REMIT_IDENTITY")]
        identity: PathBuf,
        /// An admissible program (default: the catalog's first example).
        #[arg(long)]
        program: Option<PathBuf>,
    },
    /// Replay audit: re-run a recorded remit on the same data versions and
    /// compare `result_sha256` (Holder side; spends no budget).
    Replay {
        #[arg(short, long, default_value = "remit.toml")]
        config: PathBuf,
        /// The submitted DSSE envelope.
        #[arg(long)]
        envelope: PathBuf,
        /// The receipt to audit (envelope, or a response containing one).
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Measure the performance targets on this machine.
    Bench {
        #[arg(long, default_value = "engines/js/dist/remit_engine_js.wasm")]
        engine: PathBuf,
        #[arg(long, default_value_t = 2000)]
        iterations: usize,
        #[arg(long)]
        json: bool,
        /// Measure ns per unit of fuel instead.
        #[arg(long)]
        calibrate: bool,
    },
    /// Policy tooling.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Receipt tooling.
    Receipts {
        #[command(subcommand)]
        cmd: ReceiptCmd,
    },
    /// Biscuit authority tooling.
    Authority {
        #[command(subcommand)]
        cmd: AuthorityCmd,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Promote a *draft* policy (e.g. drafted from natural language): a named
    /// human approves it and the analysis must pass, or nothing is written.
    Promote {
        draft: PathBuf,
        /// Destination `.cedar` file.
        dest: PathBuf,
        #[arg(long)]
        approved_by: String,
        #[arg(short, long, default_value = "remit.toml")]
        config: PathBuf,
    },
    /// Validate (Cedar strict) and find shadowed / always-allow / never-satisfiable rules.
    Lint {
        #[arg(short, long, default_value = "remit.toml")]
        config: PathBuf,
    },
    /// Decisions that change between two policy files over the catalog's request space.
    Diff {
        before: PathBuf,
        after: PathBuf,
        #[arg(short, long, default_value = "remit.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ReceiptCmd {
    /// Verify a receipt (JSON envelope) or a whole receipt log (JSONL).
    Verify {
        file: PathBuf,
        /// Holder key (`did:key:…`).
        #[arg(long)]
        holder_key: Option<String>,
        /// Also require TEE evidence: a JSON file `{root, pcrs, max_age_ms}`.
        #[arg(long)]
        attestation: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AuthorityCmd {
    /// Create a Biscuit root key pair.
    Keygen,
    /// Issue a token with Datalog facts/checks.
    Issue {
        #[arg(long)]
        root_private: String,
        #[arg(long)]
        code: String,
    },
    /// Attenuate a token with an extra block of checks.
    Attenuate {
        token: String,
        #[arg(long)]
        root_public: String,
        #[arg(long)]
        code: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Workers confine themselves before any runtime thread exists.
    match cli.cmd {
        Cmd::WorkerSelftest { secret_file } => {
            println!(
                "{}",
                serde_json::to_string(&remit_kernel::worker::selftest(&secret_file))?
            );
            Ok(())
        }
        Cmd::CompileWorker { max_memory_bytes } => {
            remit_kernel::worker::compile_stdio(max_memory_bytes)
        }
        Cmd::KernelWorker {
            engine,
            sha256,
            cache_dir,
            lang,
            max_memory_bytes,
        } => remit_kernel::worker::serve_stdio(remit_kernel::EngineConfig {
            component: engine,
            sha256,
            cache_dir,
            pool_instances: 8,
            lang,
            max_memory_bytes,
            ..Default::default()
        }),
        _ => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run(cli)),
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with_writer(std::io::stderr)
            .init();
    }
    match cli.cmd {
        Cmd::Serve { config, listen } => {
            let mut cfg = remit_holder::Config::load(&config)?;
            if let Some(l) = listen {
                cfg.holder.listen = l;
            }
            let h = remit_holder::Holder::from_config(cfg).await?;
            eprintln!(
                "remit holder {} on http://{} (isolation: {})",
                h.id(),
                h.cfg.holder.listen,
                h.cfg.holder.isolation
            );
            remit_holder::serve(h).await?;
        }
        Cmd::WorkerSelftest { .. } | Cmd::CompileWorker { .. } | Cmd::KernelWorker { .. } => {
            unreachable!("handled before the runtime starts")
        }
        Cmd::Keygen { p256, id, out } => {
            let s = if p256 {
                remit_wire::Signer::generate_p256(id)
            } else {
                remit_wire::Signer::generate(id)
            };
            let text = serde_json::to_string_pretty(&s.to_file())?;
            match out {
                Some(p) => {
                    s.save_new(&p)?;
                    eprintln!(
                        "wrote {} ({}; public key {})",
                        p.display(),
                        s.id(),
                        s.did_key()
                    );
                }
                None => println!("{text}"),
            }
        }
        Cmd::Sign {
            manifest,
            identity,
            holder_id,
            out,
        } => {
            let s = remit_wire::Signer::load(&identity).map_err(|e| anyhow!("{e}"))?;
            let m: Value = serde_json::from_str(&std::fs::read_to_string(&manifest)?)?;
            let env = sender::sign(m, &s, holder_id.as_deref())?;
            let text = serde_json::to_string_pretty(&env)?;
            match out {
                Some(p) => std::fs::write(p, text)?,
                None => println!("{text}"),
            }
        }
        Cmd::Check {
            file,
            holder,
            identity,
        } => {
            let v = sender::submit(&file, &holder, identity.as_deref(), "check", false).await?;
            print_decision(&v);
        }
        Cmd::Explain {
            file,
            holder,
            identity,
        } => {
            let v = sender::submit(&file, &holder, identity.as_deref(), "check", false).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "decision": v["decision"], "access_card": v["access_card"], "facts": v["facts"], "cost": v["cost"],
                    "trace": v["trace"], "diagnostics": v["diagnostics"], "warnings": v["warnings"],
                }))?
            );
        }
        Cmd::Run {
            file,
            holder,
            identity,
            accept_counter_offers,
        } => {
            let v = sender::submit(
                &file,
                &holder,
                identity.as_deref(),
                "run",
                accept_counter_offers,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            if v.get("status").and_then(Value::as_str) != Some("ok") {
                std::process::exit(2);
            }
        }
        Cmd::Lint { manifest } => {
            let m: Value = serde_json::from_str(&std::fs::read_to_string(&manifest)?)?;
            let report = sender::lint(&m);
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["ok"] != json!(true) {
                std::process::exit(1);
            }
        }
        Cmd::Pull { holder, name, dir } => codegen::pull(&holder, name, &dir).await?,
        Cmd::Dev {
            catalog,
            listen,
            engine,
            rows,
        } => dev::run(&catalog, &listen, &engine, rows).await?,
        Cmd::Bench {
            engine,
            calibrate: true,
            ..
        } => bench::calibrate(&engine).await?,
        Cmd::Bench {
            engine,
            iterations,
            json,
            ..
        } => bench::run(&engine, iterations, json).await?,
        Cmd::Conformance {
            holder,
            identity,
            program,
        } => {
            if !conformance::run(&holder, &identity, program.as_deref()).await? {
                std::process::exit(1);
            }
        }
        Cmd::Replay {
            config,
            envelope,
            receipt,
        } => {
            let mut cfg = remit_holder::Config::load(&config)?;
            // Never touch the live ledger, log or nonce cache.
            let scratch = std::env::temp_dir().join(format!("remit-replay-{}", std::process::id()));
            let live_data = cfg.resolve(&cfg.holder.data_dir);
            if cfg.holder.identity.is_none() {
                cfg.holder.identity =
                    Some(live_data.join("holder-identity.json").display().to_string());
            }
            cfg.holder.data_dir = scratch.display().to_string();
            let h = remit_holder::Holder::from_config(cfg).await?;
            let env: remit_wire::Envelope =
                serde_json::from_str(&std::fs::read_to_string(&envelope)?)?;
            let mut m: Value =
                serde_json::from_slice(&env.payload_bytes().map_err(|e| anyhow!("{e}"))?)?;
            if m.get("code")
                .is_some_and(|c| c.get("source").and_then(Value::as_str).is_none())
            {
                let hash = remit_wire::manifest::normalize_hash(
                    m["code"]["source_sha256"]
                        .as_str()
                        .ok_or_else(|| anyhow!("missing source hash"))?,
                );
                anyhow::ensure!(
                    hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()),
                    "invalid source hash"
                );
                let source = std::fs::read_to_string(live_data.join("blobs").join(&hash))?;
                anyhow::ensure!(
                    remit_wire::sha256_hex(source.as_bytes()) == hash,
                    "code hash does not match source"
                );
                m["code"]["source"] = json!(source);
            }
            let rv: Value = serde_json::from_str(&std::fs::read_to_string(&receipt)?)?;
            let renv: remit_wire::Envelope =
                serde_json::from_value(rv.get("receipt").cloned().unwrap_or(rv))?;
            let rc = remit_receipt::Receipt::verify(&renv, &h.signer.public_key())
                .map_err(|e| anyhow!("receipt: {e}"))?;
            let out = remit_holder::run::replay(
                &h,
                remit_wire::Manifest::from_value(m).map_err(|e| anyhow!("{e}"))?,
                &rc,
            )
            .await;
            let _ = std::fs::remove_dir_all(&scratch);
            println!("{}", out?);
        }
        Cmd::Policy { cmd } => {
            match cmd {
                PolicyCmd::Lint { config } => {
                    let cfg = remit_holder::Config::load(&config)?;
                    let (text, res, principals) = policy_inputs(&cfg)?;
                    let f = remit_policy::lint::lint(&text, &res, &principals);
                    if f.is_empty() {
                        println!(
                            "policy ok ({} resources, {} principals)",
                            res.len(),
                            principals.len()
                        );
                    }
                    for x in &f {
                        println!(
                            "{}: {}{}",
                            x.level,
                            x.policy
                                .as_ref()
                                .map(|p| format!("[{p}] "))
                                .unwrap_or_default(),
                            x.message
                        );
                    }
                    if f.iter().any(|x| x.level == "error") {
                        std::process::exit(1);
                    }
                }
                PolicyCmd::Promote {
                    draft,
                    dest,
                    approved_by,
                    config,
                } => {
                    let cfg = remit_holder::Config::load(&config)?;
                    let (_, res, principals) = policy_inputs(&cfg)?;
                    let text = std::fs::read_to_string(&draft)?;
                    let full = remit_policy::presets::assemble(
                        &[],
                        &[(draft.display().to_string(), text.clone())],
                    )
                    .map_err(|e| anyhow!(e))?;
                    let f = remit_policy::lint::lint(&full, &res, &principals);
                    for x in &f {
                        println!(
                            "{}: {}{}",
                            x.level,
                            x.policy
                                .as_ref()
                                .map(|p| format!("[{p}] "))
                                .unwrap_or_default(),
                            x.message
                        );
                    }
                    anyhow::ensure!(
                        !approved_by.trim().is_empty(),
                        "--approved-by must name the human approver"
                    );
                    anyhow::ensure!(
                        !f.iter()
                            .any(|x| x.message.starts_with("sampled, not proved")),
                        "a draft can only be promoted when the analysis is a proof (install z3)"
                    );
                    anyhow::ensure!(
                        !f.iter().any(|x| x.level != "info"),
                        "the draft has findings; fix them first"
                    );
                    anyhow::ensure!(
                        !dest.exists(),
                        "{} already exists; review `remit policy diff` and replace it deliberately",
                        dest.display()
                    );
                    std::fs::write(&dest, format!("// Promoted from a draft; approved by {} on {}. Analysis: proved.\n{text}", approved_by.trim(), chrono::Utc::now().date_naive()))?;
                    println!("promoted to {}", dest.display());
                }
                PolicyCmd::Diff {
                    before,
                    after,
                    config,
                } => {
                    let cfg = remit_holder::Config::load(&config)?;
                    let (_, res, principals) = policy_inputs(&cfg)?;
                    let base = remit_policy::presets::assemble(&cfg.policy.presets, &[])
                        .map_err(|e| anyhow!(e))?;
                    let b = format!("{base}\n{}", std::fs::read_to_string(&before)?);
                    let a = format!("{base}\n{}", std::fs::read_to_string(&after)?);
                    match remit_policy::lint::prove_equivalent(&b, &a, &res) {
                        Ok(None) => {
                            println!("equivalent: no request is decided differently (proved)");
                            return Ok(());
                        }
                        Ok(Some(ex)) => println!("not equivalent (proved); example: {ex}"),
                        Err(e) => println!("sampled, not proved: {e}"),
                    }
                    let d = remit_policy::lint::diff(&b, &a, &res, &principals)
                        .map_err(|e| anyhow!(e))?;
                    println!("{} decision(s) change", d.len());
                    for e in d.iter().take(50) {
                        println!(
                            "{} {} {} : {} → {}  ctx={}",
                            e.principal, e.action, e.resource, e.before, e.after, e.context
                        );
                    }
                }
            }
        }
        Cmd::Receipts {
            cmd:
                ReceiptCmd::Verify {
                    file,
                    holder_key,
                    attestation,
                },
        } => {
            let key = holder_key
                .as_deref()
                .map(|k| {
                    remit_wire::public_key_from_did_key(k)
                        .ok_or_else(|| anyhow!("holder key must be a did:key"))
                })
                .transpose()?;
            let text = std::fs::read_to_string(&file)?;
            if file.extension().is_some_and(|e| e == "jsonl") {
                let n =
                    remit_receipt::verify_log(&file, key.as_ref()).map_err(|e| anyhow!("{e}"))?;
                println!(
                    "receipt log ok: {n} entries, chain intact{}",
                    if key.is_some() {
                        ", signatures valid"
                    } else {
                        ""
                    }
                );
            } else {
                let v: Value = serde_json::from_str(&text)?;
                let env_v = v.get("receipt").cloned().unwrap_or(v);
                let env: remit_wire::Envelope = serde_json::from_value(env_v)?;
                let k = key.ok_or_else(|| {
                    anyhow!("--holder-key is required to verify a single receipt")
                })?;
                let r = remit_receipt::Receipt::verify(&env, &k).map_err(|e| anyhow!("{e}"))?;
                if let Some(p) = attestation {
                    let want: remit_receipt::attest::Expectation =
                        serde_json::from_str(&std::fs::read_to_string(p)?)?;
                    let v = remit_receipt::attest::verify(
                        &r,
                        &want,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .map_err(|e| anyhow!("{e}"))?;
                    println!("attestation ok: {}", serde_json::to_string(&v)?);
                }
                println!("receipt ok: {}", serde_json::to_string_pretty(&r)?);
            }
        }
        Cmd::Authority { cmd } => match cmd {
            AuthorityCmd::Keygen => {
                let kp = biscuit_auth::PrivateKey::new();
                println!(
                    "{}",
                    json!({"private": kp.to_prefixed_string(), "public": kp.public().to_string()})
                );
            }
            AuthorityCmd::Issue { root_private, code } => {
                let pk: biscuit_auth::PrivateKey =
                    root_private.parse().map_err(|e| anyhow!("{e:?}"))?;
                let kp = biscuit_auth::PrivateKey::from(&pk);
                println!(
                    "{}",
                    remit_policy::authority::issue(&kp, &code).map_err(|e| anyhow!("{e}"))?
                );
            }
            AuthorityCmd::Attenuate {
                token,
                root_public,
                code,
            } => {
                let pk: biscuit_auth::PublicKey =
                    root_public.parse().map_err(|e| anyhow!("{e:?}"))?;
                println!(
                    "{}",
                    remit_policy::authority::attenuate(&token, pk, &code)
                        .map_err(|e| anyhow!("{e}"))?
                );
            }
        },
    }
    Ok(())
}

fn policy_inputs(
    cfg: &remit_holder::Config,
) -> anyhow::Result<(
    String,
    std::collections::BTreeMap<String, remit_read::ResourceConfig>,
    Vec<remit_policy::PrincipalInfo>,
)> {
    let mut files = Vec::new();
    for pat in &cfg.policy.files {
        let full = cfg.resolve(pat);
        for p in glob_paths(&full)? {
            files.push((
                p.display().to_string(),
                std::fs::read_to_string(&p).with_context(|| p.display().to_string())?,
            ));
        }
    }
    let text =
        remit_policy::presets::assemble(&cfg.policy.presets, &files).map_err(|e| anyhow!(e))?;
    let principals = cfg.principals.iter().map(|p| p.info()).collect();
    Ok((text, cfg.resources()?, principals))
}

fn glob_paths(p: &std::path::Path) -> anyhow::Result<Vec<PathBuf>> {
    let s = p.to_string_lossy();
    if !s.contains('*') {
        return Ok(vec![p.to_path_buf()]);
    }
    let dir = p.parent().unwrap_or(std::path::Path::new("."));
    let suffix = p
        .file_name()
        .map(|f| f.to_string_lossy().trim_start_matches('*').to_string())
        .unwrap_or_default();
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|x| x.to_string_lossy().ends_with(&suffix))
        .collect();
    out.sort();
    Ok(out)
}

fn print_decision(v: &Value) {
    let d = v["decision"].as_str().unwrap_or("?");
    println!("decision: {d}");
    if let Some(f) = v.get("facts").filter(|f| !f.is_null()) {
        println!(
            "result_bits: {}  (capacity {} bits)  aggregate_only: {}",
            f["result_bits"], f["capacity_bits"], f["aggregate_only"]
        );
    }
    for key in ["diagnostics", "warnings"] {
        if let Some(ds) = v.get(key).and_then(Value::as_array) {
            for x in ds {
                let span = x
                    .get("span")
                    .and_then(|s| s.as_array())
                    .map(|s| format!(" (line {}, col {})", s[0], s[1]))
                    .unwrap_or_default();
                println!(
                    "  {} {} at {}{}: {}",
                    if key == "warnings" {
                        "warning"
                    } else {
                        "error"
                    },
                    x["code"].as_str().unwrap_or(""),
                    x["path"].as_str().unwrap_or(""),
                    span,
                    x["message"].as_str().unwrap_or("")
                );
                if let Some(h) = x.get("hint").and_then(Value::as_str) {
                    println!("      hint: {h}");
                }
                if let Some(f) = x.get("fix") {
                    println!("      fix: {f}");
                }
            }
        }
    }
    if let Some(c) = v.get("counter_offer") {
        println!("counter-offer: {}", c["json_patch"]);
    }
}
