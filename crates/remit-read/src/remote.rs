//! Remote object stores (`s3://`, `gs://`, `az://`) for file-based sources.
//!
//! A Remit source is a pinned snapshot that is fully read at load time, so a
//! remote source is fetched once into a private directory, read by the ordinary
//! loader, and deleted. Nothing a Sender does can cause a remote request.
//! Credentials come only from the Holder's environment (`AWS_*`, `GOOGLE_*`,
//! `AZURE_*`).

use std::path::PathBuf;
use std::sync::Arc;

use futures::TryStreamExt;
use object_store::path::Path as Key;
use object_store::{ObjectStore, ObjectStoreExt};
use tokio::io::AsyncWriteExt;

use crate::config::SourceConfig;
use crate::ReadError;

const DEFAULT_MAX_BYTES: u64 = 4 << 30;
const MAX_OBJECTS: usize = 100_000;

/// A fetched copy; removed when dropped.
pub struct Mirror {
    pub dir: PathBuf,
    /// Path (or glob) relative to `dir`.
    pub path: String,
}

impl Drop for Mirror {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn open(scheme: &str, bucket: &str) -> Result<Arc<dyn ObjectStore>, object_store::Error> {
    use object_store::{
        aws::AmazonS3Builder, azure::MicrosoftAzureBuilder, gcp::GoogleCloudStorageBuilder,
    };
    Ok(match scheme {
        "s3" => Arc::new(
            AmazonS3Builder::from_env()
                .with_bucket_name(bucket)
                .build()?,
        ),
        "gs" => Arc::new(
            GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(bucket)
                .build()?,
        ),
        _ => Arc::new(
            MicrosoftAzureBuilder::from_env()
                .with_container_name(bucket)
                .build()?,
        ),
    })
}

/// Split `a/b/*.parquet` into the literal prefix `a/b` and the rest. Without a
/// glob, the last component is the rest.
fn split(p: &str) -> (Vec<&str>, Vec<&str>) {
    let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    let n = parts
        .iter()
        .position(|s| s.contains(['*', '?', '[']))
        .unwrap_or(parts.len().saturating_sub(1));
    (parts[..n].to_vec(), parts[n..].to_vec())
}

pub async fn mirror(src: &SourceConfig) -> Result<Mirror, ReadError> {
    let url = src.path.as_deref().unwrap_or("");
    let bad = |m: String| ReadError::Config(format!("source `{}`: {m}", src.name));
    let (scheme, rest) = url.split_once("://").unwrap_or(("", ""));
    if !matches!(scheme, "s3" | "gs" | "az") {
        return Err(bad(format!(
            "unsupported URL scheme `{scheme}` (s3 | gs | az)"
        )));
    }
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket.is_empty() || key.trim_matches('/').is_empty() {
        return Err(bad("a remote path needs a bucket and a key prefix".into()));
    }
    let store = open(scheme, bucket).map_err(|e| bad(e.to_string()))?;
    fetch(
        store.as_ref(),
        key,
        src.max_bytes.unwrap_or(DEFAULT_MAX_BYTES),
    )
    .await
    .map_err(bad)
}

async fn fetch(store: &dyn ObjectStore, key: &str, max_bytes: u64) -> Result<Mirror, String> {
    let (prefix, tail) = split(key);
    let list_at: Vec<&str> = if tail.len() == 1 && !tail[0].contains(['*', '?', '[']) {
        prefix.iter().chain(&tail).copied().collect()
    } else {
        prefix.clone()
    };
    let exact = Key::parse(list_at.join("/")).map_err(|e| e.to_string())?;
    let mut objects: Vec<object_store::ObjectMeta> = Vec::new();
    let mut total = 0u64;
    // A single object, or everything below a prefix.
    if let (false, Ok(m)) = (list_at.is_empty(), store.head(&exact).await) {
        total = m.size;
        objects.push(m);
    } else {
        let mut s = store.list(Some(&exact));
        while let Some(m) = s.try_next().await.map_err(|e| e.to_string())? {
            total = total.saturating_add(m.size);
            objects.push(m);
            if objects.len() > MAX_OBJECTS {
                return Err(format!("more than {MAX_OBJECTS} objects"));
            }
        }
    }
    if total > max_bytes {
        return Err(format!(
            "{total} bytes exceed the {max_bytes}-byte limit (`max_bytes`)"
        ));
    }
    if objects.is_empty() {
        return Err(format!("no objects at `{key}`"));
    }
    let mut seed = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
        .map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir().join(format!("remit-remote-{}", hex::encode(seed)));
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir).map_err(|e| e.to_string())?;
    let out = Mirror {
        dir,
        path: tail.join("/"),
    };
    let mut got = 0u64;
    for m in objects {
        let full = m.location.as_ref();
        // Directory markers.
        if m.size == 0 && full.ends_with('/') {
            continue;
        }
        let rel: Vec<&str> = full.split('/').skip(prefix.len()).collect();
        if rel.is_empty()
            || rel
                .iter()
                .any(|c| c.is_empty() || matches!(*c, "." | "..") || c.contains(['\\', '\0']))
        {
            return Err(format!("object key `{full}` cannot be stored safely"));
        }
        let to = rel.iter().fold(out.dir.clone(), |p, c| p.join(c));
        if let Some(d) = to.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        // Pin to what was listed: a replaced object fails instead of mixing versions.
        let opts = object_store::GetOptions {
            if_match: m.e_tag.clone(),
            ..Default::default()
        };
        let mut body = store
            .get_opts(&m.location, opts)
            .await
            .map_err(|e| e.to_string())?
            .into_stream();
        let mut f = tokio::fs::File::create_new(&to)
            .await
            .map_err(|e| e.to_string())?;
        while let Some(chunk) = body.try_next().await.map_err(|e| e.to_string())? {
            got += chunk.len() as u64;
            if got > max_bytes {
                return Err("the store sent more bytes than it listed".into());
            }
            f.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        f.flush().await.map_err(|e| e.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    async fn put(s: &InMemory, k: &str, v: &str) {
        s.put(&Key::parse(k).unwrap(), v.to_string().into())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fetches_files_globs_and_directories_then_cleans_up() {
        let s = InMemory::new();
        put(&s, "lake/t/_delta_log/0.json", "{}").await;
        put(&s, "lake/t/a.csv", "x\n1\n").await;
        put(&s, "lake/t/b.csv", "x\n2\n").await;
        put(&s, "lake/tother/c.csv", "x\n3\n").await;
        let m = fetch(&s, "lake/t", 1 << 20).await.unwrap();
        assert!(m.dir.join("t/_delta_log/0.json").exists() && m.path == "t");
        assert!(
            !m.dir.join("tother").exists(),
            "a prefix is a directory, not a string prefix"
        );
        let d = m.dir.clone();
        drop(m);
        assert!(!d.exists());
        let m = fetch(&s, "lake/t/*.csv", 1 << 20).await.unwrap();
        assert!(m.dir.join("a.csv").exists() && m.path == "*.csv");
        let m = fetch(&s, "lake/t/a.csv", 1 << 20).await.unwrap();
        assert!(m.dir.join("a.csv").exists() && !m.dir.join("b.csv").exists());
        assert!(fetch(&s, "lake/t", 5).await.is_err(), "size limit");
        assert!(fetch(&s, "lake/none", 1 << 20).await.is_err());
        assert!(fetch(&s, "lake/../t", 1 << 20).await.is_err());
    }

    #[tokio::test]
    async fn only_object_store_schemes() {
        for p in [
            "http://169.254.169.254/x",
            "file:///etc/passwd",
            "s3://bucket",
            "ftp://a/b",
        ] {
            let src = SourceConfig {
                name: "x".into(),
                kind: "csv".into(),
                path: Some(p.into()),
                ..Default::default()
            };
            assert!(mirror(&src).await.is_err(), "{p}");
        }
    }

    /// A minimal S3 server over TCP: requires a SigV4 header, serves one CSV.
    #[tokio::test]
    async fn s3_source_end_to_end() {
        use tokio::io::AsyncReadExt;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut c, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        let n = c.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        req.extend_from_slice(&buf[..n]);
                    }
                    let req = String::from_utf8_lossy(&req).to_string();
                    let signed = req.contains("AWS4-HMAC-SHA256 Credential=testkey/");
                    let body = "id,name\n1,ann\n2,bob\n";
                    let resp = if !signed {
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    } else if req.contains("/bkt/data/people.csv") {
                        let head = req.starts_with("HEAD");
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"e1\"\r\nLast-Modified: Mon, 02 Nov 2026 00:00:00 GMT\r\nConnection: close\r\n\r\n{}", body.len(), if head { "" } else { body })
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    };
                    let _ = c.write_all(resp.as_bytes()).await;
                });
            }
        });
        use object_store::aws::AmazonS3Builder;
        let s3 = |key: &str| {
            AmazonS3Builder::new()
                .with_bucket_name("bkt")
                .with_region("us-east-1")
                .with_endpoint(format!("http://{addr}"))
                .with_allow_http(true)
                .with_access_key_id(key)
                .with_secret_access_key("s")
                .build()
                .unwrap()
        };
        let m = fetch(&s3("testkey"), "data/people.csv", 1 << 20)
            .await
            .unwrap();
        let mut st = crate::store::Store::new();
        let src = SourceConfig {
            name: "hr".into(),
            kind: "csv".into(),
            path: Some(m.path.clone()),
            ..Default::default()
        };
        st.load_source(&src, &m.dir).await.unwrap();
        assert_eq!(st.get("hr.people").unwrap().rows, 2);
        assert!(fetch(&s3("wrong"), "data/people.csv", 1 << 20)
            .await
            .is_err());
    }
}
