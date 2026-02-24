use cmr_core::protocol::{CmrMessage, CmrTimestamp, MessageId, Signature};
use cmr_peer::app::start_peer;
use cmr_peer::config::{EXAMPLE_CONFIG_TOML, PeerConfig};
use http_body_util::Full;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::time::Duration;
use tokio::net::TcpStream;

fn allocate_local_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

#[tokio::test]
async fn test_persistence_across_restarts() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = PeerConfig::from_toml_str(EXAMPLE_CONFIG_TOML)?;

    // Use a unique storage path for this test
    let temp_dir = std::env::temp_dir().join(format!("cmr-test-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir)?;
    let storage_path = temp_dir.join("test-messages.zpaq");
    config.storage.enabled = true;
    config.storage.path = storage_path.to_str().unwrap().to_owned();

    // Set a local address and HTTP listener
    let port = allocate_local_port()?;
    config.local_address = format!("http://127.0.0.1:{port}/");
    if let Some(http) = config.listen.http.as_mut() {
        http.bind = format!("127.0.0.1:{port}");
    }
    // Disable other listeners to avoid conflicts
    config.listen.https = None;
    config.listen.udp = None;
    config.listen.smtp = None;

    // ensure the compressor binary exists; `cmr-peer` tests run independently of cmr-compressor
    // so build it explicitly and point the config at the resulting executable. this avoids spawn
    // errors when the binary isn't on PATH (CI was failing earlier).
    //
    // cargo automatically places workspace binaries under target/(debug|release)/,
    // and our test binary lives in target/debug/deps; climb up two levels to reach the
    // workspace target directory.
    let workdir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(|p| p.to_path_buf())
        .expect("unable to compute workspace root");
    let bin_name = format!("cmr-compressor{}", std::env::consts::EXE_SUFFIX);
    let bin_path = workdir.join("target").join("debug").join(bin_name);
    if !bin_path.is_file() {
        // build compressor using cargo; ignore output but fail the test if build fails.
        // build the compressor binary if necessary; attributes must be
        // placed outside the chained call.
        let mut cmd = std::process::Command::new("cargo");
        cmd.current_dir(&workdir);
        #[allow(clippy::needless_borrows_for_generic_args)]
        cmd.args(&["build", "-p", "cmr-compressor"]);
        let status = cmd.status()?;
        assert!(
            status.success(),
            "failed to build cmr-compressor for persistence test"
        );
        assert!(bin_path.is_file(), "built compressor binary not found");
    }
    // point the nested compressor config at the explicit path so that the
    // worker client doesn't try to spawn a missing command from PATH.
    config.compressor.command = bin_path.to_string_lossy().to_string();

    // 1. Start the peer first time
    let runtime = start_peer(config.clone()).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 2. Ingest a message
    let message = CmrMessage {
        signature: Signature::Unsigned,
        header: vec![MessageId {
            timestamp: CmrTimestamp::now_utc(),
            address: "http://sender.example/".to_owned(),
        }],
        body: b"persistence test message".to_vec(),
    };
    let payload = message.to_bytes();

    {
        let stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::post("/").body(Full::new(bytes::Bytes::from(payload.clone())))?;
        let res = sender.send_request(req).await?;
        assert!(res.status().is_success(), "First ingest should succeed");
    }

    // 3. Shutdown the peer
    runtime.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Start the peer again
    let runtime2 = start_peer(config.clone()).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 5. Verify the message is still there by trying to ingest the same message again.
    // It should be rejected as a duplicate because it was loaded from zpaq.
    {
        let stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::post("/").body(Full::new(bytes::Bytes::from(payload)))?;
        let res = sender.send_request(req).await?;

        // Peer returns 400 Bad Request for duplicate message IDs
        assert_eq!(
            res.status().as_u16(),
            400,
            "Second ingest should fail as duplicate after reload"
        );
    }

    runtime2.shutdown().await;
    let _ = std::fs::remove_dir_all(temp_dir);

    Ok(())
}
