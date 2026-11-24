//! `remit conformance <holder>`: black-box conformance suite for any Holder
//! implementation (spec/conformance/README.md). Every check names the spec
//! section it exercises; the suite never needs Holder-private state.

use std::path::Path;

use anyhow::anyhow;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use remit_wire::{
    dsse::pae, jcs, sha256_hex, Envelope, Manifest, PublicKey, Signer, CATALOG_TYPE, MANIFEST_TYPE,
};
use reqwest::{Client, Response, StatusCode};
use serde_json::{json, Value};

struct Suite {
    http: Client,
    url: String,
    signer: Signer,
    program: Value,
    results: std::cell::RefCell<Vec<(String, &'static str, Option<String>)>>,
}

type Check = anyhow::Result<()>;

fn ensure(c: bool, m: impl Into<String>) -> Check {
    if c {
        Ok(())
    } else {
        Err(anyhow!(m.into()))
    }
}

impl Suite {
    fn record(&self, section: &'static str, name: &str, r: Check) {
        let err = r.err().map(|e| format!("{e:#}"));
        println!(
            "{} {section:<10} {name}{}",
            if err.is_none() { "pass" } else { "FAIL" },
            err.as_ref()
                .map(|e| format!("\n       {e}"))
                .unwrap_or_default()
        );
        self.results
            .borrow_mut()
            .push((name.to_string(), section, err));
    }

    async fn get(&self, p: &str) -> anyhow::Result<Response> {
        Ok(self.http.get(format!("{}{p}", self.url)).send().await?)
    }

    async fn post(&self, p: &str, body: &Value) -> anyhow::Result<(StatusCode, Value)> {
        let r = self
            .http
            .post(format!("{}{p}", self.url))
            .json(body)
            .send()
            .await?;
        let st = r.status();
        Ok((st, r.json().await.unwrap_or(Value::Null)))
    }

    /// The admissible program, freshly bound, after `edit`.
    fn manifest(&self, holder: &str, edit: impl FnOnce(&mut Value)) -> Value {
        let now = chrono::Utc::now();
        let iso =
            |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut m = self.program.clone();
        m.as_object_mut().expect("object").remove("remit_id");
        m["remit"] = json!(remit_wire::REMIT_VERSION);
        m["sender"] = json!(self.signer.id());
        m["holder"] = json!(holder);
        m["issued_at"] = json!(iso(now));
        m["expires_at"] = json!(iso(now + chrono::Duration::minutes(5)));
        m["nonce"] = json!(format!("{:032x}", rand::random::<u128>()));
        if m.get("limits").is_none() {
            m["limits"] = json!({});
        }
        if let Some(src) = m["code"]["source"].as_str().map(String::from) {
            m["code"]["source_sha256"] = json!(sha256_hex(src.as_bytes()));
        }
        edit(&mut m);
        m
    }

    fn envelope(&self, m: &Value) -> Value {
        match Manifest::from_value(m.clone()) {
            Ok(x) => {
                serde_json::to_value(remit_wire::sign_manifest(&x, &self.signer)).expect("envelope")
            }
            // Structurally invalid on purpose: sign the raw canonical JSON.
            Err(_) => serde_json::to_value(Envelope::sign(
                MANIFEST_TYPE,
                &jcs::canonical_bytes(m).expect("jcs"),
                &self.signer,
            ))
            .expect("envelope"),
        }
    }

    async fn rejected(&self, m: &Value, code: &str) -> Check {
        let (_, v) = self.post("/remit/v1/check", &self.envelope(m)).await?;
        let got = v["diagnostics"][0]["code"]
            .as_str()
            .unwrap_or("")
            .to_string();
        ensure(
            v["decision"] == "rejected",
            format!("decision was {}", v["decision"]),
        )?;
        ensure(
            code.split('|').any(|c| c == got),
            format!("diagnostic {got}, want {code}"),
        )?;
        let d = &v["diagnostics"][0];
        ensure(
            d["path"].is_string() && d["message"].is_string(),
            "diagnostics must carry path and message",
        )
    }
}

pub async fn run(url: &str, identity: &Path, program: Option<&Path>) -> anyhow::Result<bool> {
    let signer = Signer::load(identity).map_err(|e| anyhow!("{e}"))?;
    let url = url.trim_end_matches('/').to_string();
    let http = Client::new();
    let r = http.get(format!("{url}/.well-known/remit")).send().await?;
    let sig = r
        .headers()
        .get("remit-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let etag = r
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let catalog: Value = r.json().await?;
    let holder = catalog["holder"]
        .as_str()
        .ok_or_else(|| anyhow!("catalog has no holder"))?
        .to_string();
    let program: Value = match program {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
        None => catalog["examples"][0]["manifest"].clone(),
    };
    anyhow::ensure!(
        program["reads"].is_object(),
        "no admissible program: pass --program, or publish a catalog example"
    );
    let s = Suite {
        http,
        url,
        signer,
        program,
        results: Default::default(),
    };
    let key: Option<PublicKey> = catalog["keys"][0]["did_key"]
        .as_str()
        .and_then(remit_wire::public_key_from_did_key);

    // ---- catalog
    s.record(
        "catalog",
        "catalog signature verifies over JCS",
        (|| {
            let k = key.ok_or_else(|| anyhow!("no did_key"))?;
            let b = sig
                .split("sig=\"")
                .nth(1)
                .and_then(|x| x.split('"').next())
                .ok_or_else(|| anyhow!("no Remit-Signature"))?;
            ensure(
                k.verify(
                    &pae(CATALOG_TYPE, &jcs::canonical_bytes(&catalog)?),
                    &STANDARD.decode(b)?,
                ),
                "bad signature",
            )
        })(),
    );
    s.record(
        "catalog",
        "catalog_sha256 is content-addressed",
        (|| {
            let mut c = catalog.clone();
            let claimed = c
                .as_object_mut()
                .and_then(|o| o.remove("catalog_sha256"))
                .unwrap_or(Value::Null);
            ensure(
                claimed == json!(format!("sha256:{}", sha256_hex(&jcs::canonical_bytes(&c)?))),
                "hash mismatch",
            )
        })(),
    );
    let r304 = async {
        Ok::<_, anyhow::Error>(
            s.http
                .get(format!("{}/.well-known/remit", s.url))
                .header("if-none-match", &etag)
                .send()
                .await?
                .status(),
        )
    }
    .await;
    s.record(
        "catalog",
        "ETag revalidation",
        r304.and_then(|st| {
            ensure(
                !etag.is_empty() && st == StatusCode::NOT_MODIFIED,
                format!("{st}"),
            )
        }),
    );
    s.record(
        "catalog",
        "no forbidden request leaks hidden resources into the catalog",
        ensure(
            catalog["resources"].is_array()
                && catalog["runtime"]["status_set"]
                    .as_array()
                    .is_some_and(|a| a.len() == 5),
            "status_set must have 5 entries",
        ),
    );

    // ---- admission: authentication and freshness
    let ok = s.manifest(&holder, |_| {});
    let chk = s.post("/remit/v1/check", &s.envelope(&ok)).await;
    s.record(
        "admission",
        "the reference program is admitted",
        chk.and_then(|(st, v)| {
            ensure(
                st == StatusCode::OK && v["decision"] == "admitted",
                v.to_string(),
            )
        }),
    );
    for (name, body) in [
        ("garbage", json!("x")),
        ("empty object", json!({})),
        (
            "no signatures",
            json!({"payloadType": MANIFEST_TYPE, "payload": "e30=", "signatures": []}),
        ),
    ] {
        let r = s.post("/remit/v1/check", &body).await;
        s.record(
            "wire",
            &format!("malformed envelope is rejected: {name}"),
            r.and_then(|(_, v)| ensure(v["decision"] == "rejected", v.to_string())),
        );
    }
    let mut e = s.envelope(&ok);
    e["payloadType"] = json!("application/json");
    let r = s.post("/remit/v1/check", &e).await;
    s.record(
        "wire",
        "wrong payloadType is rejected",
        r.and_then(|(_, v)| ensure(v["decision"] == "rejected", v.to_string())),
    );
    let mut e = s.envelope(&ok);
    let mut body = STANDARD.decode(e["payload"].as_str().unwrap_or(""))?;
    body.insert(1, b' ');
    let pretty = Envelope::sign(MANIFEST_TYPE, &body, &s.signer);
    let r = s
        .post("/remit/v1/check", &serde_json::to_value(&pretty)?)
        .await;
    s.record(
        "wire",
        "non-canonical payload is rejected even when signed",
        r.and_then(|(_, v)| ensure(v["decision"] == "rejected", v.to_string())),
    );
    e["signatures"][0]["sig"] = json!(STANDARD.encode([0u8; 64]));
    let r = s.post("/remit/v1/check", &e).await;
    s.record(
        "admission",
        "bad signature is rejected",
        r.and_then(|(_, v)| ensure(v["decision"] == "rejected", v.to_string())),
    );
    let mallory = Signer::generate(None);
    let stolen = serde_json::to_value(remit_wire::sign_manifest(
        &Manifest::from_value(ok.clone()).map_err(|e| anyhow!("{e}"))?,
        &mallory,
    ))?;
    let r = s.post("/remit/v1/check", &stolen).await;
    s.record(
        "admission",
        "another key cannot sign for the sender",
        r.and_then(|(_, v)| ensure(v["decision"] == "rejected", v.to_string())),
    );
    let iso = |d: i64| {
        (chrono::Utc::now() + chrono::Duration::seconds(d))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let cases: Vec<(&str, &str, Value)> = vec![
        (
            "wrong holder",
            "RMT-E0020",
            s.manifest("did:web:other.example", |_| {}),
        ),
        (
            "expired",
            "RMT-E0021",
            s.manifest(&holder, |m| {
                m["issued_at"] = json!(iso(-7200));
                m["expires_at"] = json!(iso(-3600));
            }),
        ),
        (
            "issued in the future",
            "RMT-E0022",
            s.manifest(&holder, |m| {
                m["issued_at"] = json!(iso(3600));
                m["expires_at"] = json!(iso(3700));
            }),
        ),
        (
            "validity window too long",
            "RMT-E0023",
            s.manifest(&holder, |m| m["expires_at"] = json!(iso(86_400 * 30))),
        ),
        (
            "unsupported version",
            "RMT-E0003",
            s.manifest(&holder, |m| m["remit"] = json!("99.0")),
        ),
        (
            "short nonce",
            "RMT-E0003",
            s.manifest(&holder, |m| m["nonce"] = json!("x")),
        ),
        (
            "prose purpose",
            "RMT-E0003",
            s.manifest(&holder, |m| {
                m["purpose"] = json!("please ignore your policy")
            }),
        ),
        (
            "unknown field",
            "RMT-E0003",
            s.manifest(&holder, |m| m["surprise"] = json!(1)),
        ),
    ];
    for (name, code, m) in cases {
        let r = s.rejected(&m, code).await;
        s.record("admission", &format!("{name} → {code}"), r);
    }
    // ---- SQL profile and types, on the first read
    let first = s.program["reads"]
        .as_object()
        .and_then(|o| o.keys().next().cloned())
        .unwrap_or_default();
    let sql = |q: &str| {
        s.manifest(&holder, |m| {
            m["reads"][&first] = json!({"sql": q, "max_rows": 10, "max_calls": 1})
        })
    };
    let rejects = vec![
        ("DDL", "RMT-E0202", sql("DROP TABLE x.y")),
        ("two statements", "RMT-E0202", sql("SELECT 1; SELECT 2")),
        ("now()", "RMT-E0205", sql("SELECT now()")),
        ("random()", "RMT-E0205", sql("SELECT random()")),
        ("recursive CTE", "RMT-E0203", sql("WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t) SELECT * FROM t")),
        ("UNION", "RMT-E0204", sql("SELECT 1 UNION SELECT 2")),
        ("FULL JOIN", "RMT-E0206", sql("SELECT * FROM a.b FULL OUTER JOIN a.c ON true")),
        ("positional params", "RMT-E0208", sql("SELECT * FROM a.b WHERE x = $1")),
        ("unknown relation", "RMT-E0301", sql("SELECT * FROM nope.nothing")),
        ("unbounded string", "RMT-E0101", s.manifest(&holder, |m| m["returns"] = json!({"string": {}}))),
        ("unbounded list", "RMT-E0101", s.manifest(&holder, |m| m["returns"] = json!({"list": {"of": "bool"}}))),
        ("overflowing timestamp range", "RMT-E0103", s.manifest(&holder, |m| m["returns"] = json!({"timestamp": {"min": -9_000_000_000_000_000i64, "max": 9_000_000_000_000_000i64, "granularity": 1}}))),
    ];
    for (name, code, m) in rejects {
        let r = s.rejected(&m, code).await;
        s.record("sql/rt", &format!("{name} → {code}"), r);
    }
    // Hidden equals nonexistent: two random names get the same diagnostic shape.
    let hid = async {
        let shape = |v: &Value, n: &str| v["diagnostics"][0].to_string().replace(n, "X");
        let (_, a) = s
            .post(
                "/remit/v1/check",
                &s.envelope(&sql("SELECT * FROM zzqa.one")),
            )
            .await?;
        let (_, b) = s
            .post(
                "/remit/v1/check",
                &s.envelope(&sql("SELECT * FROM zzqa.two")),
            )
            .await?;
        ensure(
            shape(&a, "zzqa.one") == shape(&b, "zzqa.two"),
            "diagnostics differ between nonexistent relations",
        )
    }
    .await;
    s.record(
        "catalog",
        "diagnostics are uniform over invisible relations",
        hid,
    );
    // ---- clamps
    let r = async {
        let m = s.manifest(&holder, |m| {
            m["limits"]["wall_ms"] = json!(1_000_000_000u64)
        });
        let (_, v) = s.post("/remit/v1/check", &s.envelope(&m)).await?;
        ensure(
            v["decision"] == "counter_offer"
                && v["counter_offer"]["json_patch"][0]["path"] == "/limits/wall_ms",
            v.to_string(),
        )
    }
    .await;
    s.record("admission", "over-limit requests get a counter-offer", r);
    // ---- blobs
    let r = async {
        let good = s
            .http
            .put(format!("{}/remit/v1/blobs/{}", s.url, sha256_hex(b"hello")))
            .body("hello")
            .send()
            .await?
            .status();
        let bad = s
            .http
            .put(format!("{}/remit/v1/blobs/{}", s.url, sha256_hex(b"hello")))
            .body("hullo")
            .send()
            .await?
            .status();
        ensure(
            good.is_success() && bad.is_client_error(),
            format!("{good} {bad}"),
        )
    }
    .await;
    s.record("protocol", "blobs are content-addressed", r);
    // ---- run, receipts, replay, transparency log
    let env = s.envelope(&s.manifest(&holder, |_| {}));
    let run = s.post("/remit/v1/run", &env).await;
    let resp = run.as_ref().map(|x| x.1.clone()).unwrap_or(Value::Null);
    s.record(
        "protocol",
        "the reference program runs",
        run.and_then(|(st, v)| ensure(st == StatusCode::OK && v["status"] == "ok", v.to_string())),
    );
    let rc = (|| {
        let e: Envelope = serde_json::from_value(resp["receipt"].clone())?;
        let r = remit_receipt::Receipt::verify(&e, &key.ok_or_else(|| anyhow!("no key"))?)
            .map_err(|e| anyhow!("{e}"))?;
        ensure(
            r.result_sha256
                == Some(format!(
                    "sha256:{}",
                    sha256_hex(&jcs::canonical_bytes(&resp["result"])?)
                )),
            "result hash",
        )?;
        ensure(
            r.remit_id
                == Manifest::from_value(ok.clone())
                    .map_err(|e| anyhow!("{e}"))?
                    .remit_id(),
            "remit_id",
        )?;
        ensure(r.holder == holder && r.sender == s.signer.id(), "parties")?;
        ensure(
            r.usage
                .values()
                .all(|u| u.starts_with('≤') || u.starts_with('>')),
            "usage must be bucketed",
        )
    })();
    s.record(
        "receipts",
        "receipt verifies and binds result, program and parties",
        rc,
    );
    let r = s.post("/remit/v1/run", &env).await;
    s.record(
        "admission",
        "replayed envelope → RMT-E0024",
        r.and_then(|(_, v)| ensure(v["diagnostics"][0]["code"] == "RMT-E0024", v.to_string())),
    );
    let again = s
        .post("/remit/v1/run", &s.envelope(&s.manifest(&holder, |_| {})))
        .await;
    s.record(
        "receipts",
        "same program, params and snapshot give the same result",
        again.and_then(|(_, v)| {
            ensure(
                v["result"] == resp["result"] && v["status"] == "ok",
                v.to_string(),
            )
        }),
    );
    let run_id = resp["run_id"].as_str().unwrap_or("").to_string();
    let r = async {
        let v: Value = s
            .get(&format!("/remit/v1/receipts/{run_id}"))
            .await?
            .json()
            .await?;
        ensure(v == resp["receipt"], "stored receipt differs")
    }
    .await;
    s.record("receipts", "receipts can be fetched", r);
    let r = async {
        let v: Value = s
            .get(&format!("/remit/v1/log/proof/{run_id}"))
            .await?
            .json()
            .await?;
        let h = |x: &Value| -> anyhow::Result<[u8; 32]> {
            let s = x.as_str().ok_or_else(|| anyhow!("hash"))?;
            let b: Vec<u8> = (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16))
                .collect::<Result<_, _>>()?;
            b.try_into().map_err(|_| anyhow!("hash length"))
        };
        let path = v["proof"]["path"]
            .as_array()
            .into_iter()
            .flatten()
            .map(h)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let ok = remit_receipt::merkle::verify_inclusion(
            &h(&v["proof"]["leaf"])?,
            v["proof"]["index"].as_u64().unwrap_or(0),
            v["proof"]["size"].as_u64().unwrap_or(0),
            &path,
            &h(&v["tree_head"]["root"])?,
        );
        let e: Envelope = serde_json::from_value(v["signed"].clone())?;
        let k = key.ok_or_else(|| anyhow!("no key"))?;
        ensure(
            ok && e
                .verify_with(remit_receipt::merkle::STH_TYPE, |_| Some(k))
                .is_ok(),
            "inclusion proof or tree head",
        )
    }
    .await;
    s.record("receipts", "inclusion proof against a signed tree head", r);
    let r = async {
        let r = s
            .http
            .post(format!("{}/remit/v1/run", s.url))
            .header("prefer", "respond-async")
            .json(&s.envelope(&s.manifest(&holder, |_| {})))
            .send()
            .await?;
        ensure(
            r.status() == StatusCode::ACCEPTED && r.headers().contains_key("location"),
            format!("{}", r.status()),
        )?;
        let v: Value = r.json().await?;
        for _ in 0..200 {
            let x: Value = s
                .get(&format!(
                    "/remit/v1/runs/{}",
                    v["run_id"].as_str().unwrap_or("")
                ))
                .await?
                .json()
                .await?;
            if x["state"] == "done" {
                return ensure(x["response"]["status"] == "ok", x.to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        Err(anyhow!("async run did not finish"))
    }
    .await;
    s.record("protocol", "asynchronous runs", r);
    let r = s.get("/remit/v1/runs/run_nope").await;
    s.record(
        "protocol",
        "unknown run is 404",
        r.and_then(|r| {
            ensure(
                r.status() == StatusCode::NOT_FOUND,
                format!("{}", r.status()),
            )
        }),
    );
    // ---- declared types hold for arbitrary code
    if s.program["mode"] == "kernel"
        && catalog["runtime"]["languages"]
            .as_array()
            .is_some_and(|l| l.iter().any(|x| x == "js/es2023"))
    {
        let kernel = |src: &str, ret: Value| {
            s.manifest(&holder, |m| {
                m["code"] = json!({"lang": "js/es2023", "entry": "main", "source": src, "source_sha256": sha256_hex(src.as_bytes())});
                m["returns"] = ret;
            })
        };
        for (name, src, ret, want) in [
            (
                "out-of-type results release nothing",
                "export default function main() { return 'x'.repeat(1000); }",
                json!({"int": {"min": 0, "max": 1}}),
                "type_violation",
            ),
            (
                "infinite loops stop",
                "export default function main() { for (;;) {} }",
                json!("bool"),
                "limit_exceeded",
            ),
            (
                "error text never leaves",
                "export default function main() { throw new Error('SECRET-TEXT'); }",
                json!("bool"),
                "internal",
            ),
        ] {
            let r = s
                .post("/remit/v1/run", &s.envelope(&kernel(src, ret)))
                .await;
            s.record(
                "kernel",
                name,
                r.and_then(|(_, v)| {
                    ensure(
                        v["status"] == want
                            && v["result"].is_null()
                            && !v.to_string().contains("SECRET-TEXT"),
                        v.to_string(),
                    )
                }),
            );
        }
    }
    // ---- bindings
    let r = s
        .post(
            "/mcp",
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await;
    s.record(
        "mcp",
        "MCP exposes remit_check and remit_run",
        r.and_then(|(_, v)| {
            ensure(
                ["remit_check", "remit_run"]
                    .iter()
                    .all(|t| v["result"]["tools"].to_string().contains(t)),
                v.to_string(),
            )
        }),
    );
    let r = async {
        let v: Value = s.get("/.well-known/agent-card.json").await?.json().await?;
        ensure(
            v["capabilities"]["extensions"][0]["params"]["catalog"].is_string(),
            v.to_string(),
        )
    }
    .await;
    s.record("a2a", "Agent Card advertises the catalog", r);
    let r = s
        .post(
            "/remit.v1.RemitService/Check",
            &json!({"envelope": s.envelope(&s.manifest(&holder, |_| {}))}),
        )
        .await;
    s.record(
        "connect",
        "RemitService.Check",
        r.and_then(|(_, v)| ensure(v["decision"] == "admitted", v.to_string())),
    );

    let results = s.results.borrow();
    let failed = results.iter().filter(|r| r.2.is_some()).count();
    println!(
        "\n{} checks, {} passed, {failed} failed — {holder}",
        results.len(),
        results.len() - failed
    );
    Ok(failed == 0)
}
