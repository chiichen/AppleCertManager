use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use apple_cert_manager_config::Config;
use apple_cert_manager_storage::{
    sign_request, GitRepo, LocalRepo, MemoryStore, ObjectRepo, ObjectStore, Repo, S3Client,
    SignInput,
};

#[test]
fn local_repository_roundtrip_preserves_deletions() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("certs");
    let mut repo = LocalRepo::new(root.clone());
    let work = repo.open().unwrap();
    std::fs::create_dir_all(work.join("certs/distribution")).unwrap();
    std::fs::write(work.join("certs/distribution/ABC.cer"), b"one\0two\r\n").unwrap();
    std::fs::write(work.join("README.md"), b"keep").unwrap();
    repo.commit("add cert").unwrap();

    std::fs::remove_file(work.join("certs/distribution/ABC.cer")).unwrap();
    std::fs::write(work.join("certs/distribution/DEF.p12"), b"p12").unwrap();
    repo.commit("replace cert").unwrap();

    let mut again = LocalRepo::new(root);
    let work = again.open().unwrap();
    assert!(!work.join("certs/distribution/ABC.cer").exists());
    assert_eq!(
        std::fs::read(work.join("certs/distribution/DEF.p12")).unwrap(),
        b"p12"
    );
    assert_eq!(std::fs::read(work.join("README.md")).unwrap(), b"keep");
    again.commit("unchanged").unwrap();
}

#[test]
fn git_repository_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let bare = dir.path().join("certs.git");
    let status = Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&bare)
        .status()
        .unwrap();
    assert!(status.success());

    let mut repo = GitRepo::new(
        bare.display().to_string(),
        "main".into(),
        "apple-cert-manager".into(),
        "apple-cert-manager@localhost".into(),
        false,
    );
    let work = repo.open().unwrap();
    std::fs::create_dir_all(work.join("profiles/appstore")).unwrap();
    std::fs::write(
        work.join("profiles/appstore/AppStore_com.example.app.mobileprovision"),
        b"profile-bytes",
    )
    .unwrap();
    repo.commit("add profile").unwrap();

    let mut clone = GitRepo::new(
        bare.display().to_string(),
        "main".into(),
        "apple-cert-manager".into(),
        "apple-cert-manager@localhost".into(),
        true,
    );
    let work = clone.open().unwrap();
    assert_eq!(
        std::fs::read(work.join("profiles/appstore/AppStore_com.example.app.mobileprovision"))
            .unwrap(),
        b"profile-bytes"
    );
}

#[test]
fn object_repository_uses_a_prefix_and_deletes_removed_keys() {
    let store = MemoryStore::new();
    store.put("team/certs/old.cer", b"old").unwrap();
    store.put("other/skip.txt", b"no").unwrap();
    let shared = Arc::new(store);
    let mut repo = ObjectRepo::new(Box::new(SharedStore(Arc::clone(&shared))), "team");
    let work = repo.open().unwrap();
    assert!(work.join("certs/old.cer").exists());
    assert!(!work.join("skip.txt").exists());
    std::fs::remove_file(work.join("certs/old.cer")).unwrap();
    std::fs::create_dir_all(work.join("certs")).unwrap();
    std::fs::write(work.join("certs/new.cer"), b"new").unwrap();
    repo.commit("rotate").unwrap();

    assert!(shared.get("team/certs/old.cer").is_err());
    assert_eq!(shared.get("team/certs/new.cer").unwrap(), b"new");
    assert_eq!(shared.get("other/skip.txt").unwrap(), b"no");
}

#[test]
fn config_opens_a_local_repository() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    let toml = format!(
        "storage_mode = \"local\"\n\n[local]\npath = \"{}\"\n",
        path.display()
    );
    let config = Config::parse(&toml).unwrap();
    let mut repo = Repo::from_config(&config).unwrap();
    let work = repo.open().unwrap();
    std::fs::write(work.join("README.md"), b"acm").unwrap();
    repo.commit("readme").unwrap();
    assert_eq!(std::fs::read(path.join("README.md")).unwrap(), b"acm");
    assert!(repo.description().contains("local directory"));
}

#[test]
fn signs_the_published_aws_get_example() {
    let signed = sign_request(&SignInput {
        method: "GET",
        uri: "/test.txt",
        query: &[],
        host: "examplebucket.s3.amazonaws.com",
        extra_headers: &[("range", "bytes=0-9")],
        payload: b"",
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region: "us-east-1",
        service: "s3",
        amz_date: "20130524T000000Z",
    });
    assert_eq!(
        signed.signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        "canonical request:\n{}",
        signed.canonical_request
    );
}

#[test]
fn s3_client_talks_to_a_path_style_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_headers(&mut socket).expect("request");
            record.lock().unwrap().push(request);
            let body: &[u8] = if record.lock().unwrap().len() == 1 {
                br#"<?xml version="1.0" encoding="UTF-8"?>
                <ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>team/certs/ABC.cer</Key></Contents></ListBucketResult>"#
            } else {
                b"cer-bytes"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
            socket.write_all(body).unwrap();
        }
    });

    let client = S3Client::new(
        "certs".into(),
        "us-east-1".into(),
        Some(format!("http://127.0.0.1:{port}")),
        true,
        "AKIATEST".into(),
        "test-secret".into(),
    )
    .unwrap();
    let keys = ObjectStore::list(&client, "team/").unwrap();
    assert_eq!(keys, vec!["team/certs/ABC.cer".to_string()]);
    assert_eq!(
        ObjectStore::get(&client, "team/certs/ABC.cer").unwrap(),
        b"cer-bytes"
    );
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .all(|request| request.contains("AWS4-HMAC-SHA256")),
        "{requests:?}"
    );
    assert!(requests[0].contains("list-type=2"), "{}", requests[0]);
}

struct SharedStore(Arc<MemoryStore>);

impl ObjectStore for SharedStore {
    fn list(&self, prefix: &str) -> apple_cert_manager_error::Result<Vec<String>> {
        self.0.list(prefix)
    }
    fn get(&self, key: &str) -> apple_cert_manager_error::Result<Vec<u8>> {
        self.0.get(key)
    }
    fn put(&self, key: &str, body: &[u8]) -> apple_cert_manager_error::Result<()> {
        self.0.put(key, body)
    }
    fn delete(&self, key: &str) -> apple_cert_manager_error::Result<()> {
        self.0.delete(key)
    }
}

fn read_headers(socket: &mut impl Read) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if socket.read(&mut byte)? == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
