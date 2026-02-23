use std::time::Duration;

use cmr_client::{ClientTransportConfig, CmrClient, HttpInbox};
use cmr_peer::app::start_peer;
use cmr_peer::config::{HttpListenConfig, PeerConfig};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let router_alice = "http://127.0.0.1:4101/cmr";
    let router_bob = "http://127.0.0.1:4102/cmr";
    let router_charlie = "http://127.0.0.1:4103/cmr";

    let runtime_alice = start_peer(router_config(
        router_alice,
        "127.0.0.1:4101",
        &[router_bob, router_charlie],
    )?)
    .await?;
    let runtime_bob = start_peer(router_config(
        router_bob,
        "127.0.0.1:4102",
        &[router_alice, router_charlie],
    )?)
    .await?;
    let runtime_charlie = start_peer(router_config(
        router_charlie,
        "127.0.0.1:4103",
        &[router_alice, router_bob],
    )?)
    .await?;

    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut alice_inbox = HttpInbox::bind("127.0.0.1:0", "/inbox").await?;
    let mut bob_inbox = HttpInbox::bind("127.0.0.1:0", "/inbox").await?;
    let charlie_inbox = HttpInbox::bind("127.0.0.1:0", "/inbox").await?;
    let mut joe_inbox = HttpInbox::bind("127.0.0.1:0", "/inbox").await?;

    let alice = CmrClient::new(
        alice_inbox.identity().to_owned(),
        ClientTransportConfig::default(),
    )
    .await?;
    let bob = CmrClient::new(
        bob_inbox.identity().to_owned(),
        ClientTransportConfig::default(),
    )
    .await?;
    let charlie = CmrClient::new(
        charlie_inbox.identity().to_owned(),
        ClientTransportConfig::default(),
    )
    .await?;
    let joe = CmrClient::new(
        joe_inbox.identity().to_owned(),
        ClientTransportConfig::default(),
    )
    .await?;

    let router_a_bootstrap =
        CmrClient::new(router_alice.to_owned(), ClientTransportConfig::default()).await?;
    let router_b_bootstrap =
        CmrClient::new(router_bob.to_owned(), ClientTransportConfig::default()).await?;
    let router_c_bootstrap =
        CmrClient::new(router_charlie.to_owned(), ClientTransportConfig::default()).await?;

    let kex_probe = "kex-first bootstrap";
    router_a_bootstrap
        .send_body(router_bob, kex_probe, false)
        .await?;
    router_a_bootstrap
        .send_body(router_charlie, kex_probe, false)
        .await?;
    router_b_bootstrap
        .send_body(router_alice, kex_probe, false)
        .await?;
    router_b_bootstrap
        .send_body(router_charlie, kex_probe, false)
        .await?;
    router_c_bootstrap
        .send_body(router_alice, kex_probe, false)
        .await?;
    router_c_bootstrap
        .send_body(router_bob, kex_probe, false)
        .await?;

    tokio::time::sleep(Duration::from_millis(250)).await;

    bob.send_body(router_bob, "topic=planet warmup", false)
        .await?;

    alice
        .send_body(
            router_alice,
            "topic=planet prompt: What is the largest planet?",
            false,
        )
        .await?;

    let bob_question = wait_for_body_contains(
        &mut bob_inbox,
        "topic=planet prompt",
        Duration::from_secs(10),
    )
    .await;

    if bob_question.is_none() {
        println!("Bob did not receive Alice's prompt via the router mesh in time.");
        runtime_alice.shutdown().await;
        runtime_bob.shutdown().await;
        runtime_charlie.shutdown().await;
        alice_inbox.shutdown().await;
        bob_inbox.shutdown().await;
        charlie_inbox.shutdown().await;
        joe_inbox.shutdown().await;
        std::process::exit(1);
    }

    charlie
        .send_body(
            alice.identity(),
            "topic=planet answer: Jupiter is the largest planet.",
            false,
        )
        .await?;
    charlie
        .send_body(
            bob.identity(),
            "topic=planet answer: Jupiter is the largest planet.",
            false,
        )
        .await?;

    let alice_received =
        wait_for_body_contains(&mut alice_inbox, "Jupiter", Duration::from_secs(10)).await;
    let bob_received =
        wait_for_body_contains(&mut bob_inbox, "Jupiter", Duration::from_secs(10)).await;

    println!("Alice identity: {}", alice.identity());
    println!("Bob identity: {}", bob.identity());
    println!("Charlie identity: {}", charlie.identity());
    println!("Joe identity: {}", joe.identity());

    joe.send_body(
        router_alice,
        "topic=planet join: Joe is now on Alice router",
        false,
    )
    .await?;
    charlie
        .send_body(
            joe.identity(),
            "topic=planet welcome: Welcome Joe, Jupiter still wins.",
            false,
        )
        .await?;

    let joe_received =
        wait_for_body_contains(&mut joe_inbox, "Welcome Joe", Duration::from_secs(10)).await;

    match (&alice_received, &bob_received, &joe_received) {
        (Some(a), Some(b), Some(j)) => {
            println!("Alice inbox received: {a}");
            println!("Bob inbox received: {b}");
            println!("Joe inbox received: {j}");
            println!(
                "Scenario passed: three-router mesh, KEX-first warmup, and Joe join flow completed end-to-end."
            );
        }
        _ => {
            println!("Scenario did not complete in time.");
            println!("Alice match: {:?}", alice_received);
            println!("Bob match: {:?}", bob_received);
            println!("Joe match: {:?}", joe_received);
            runtime_alice.shutdown().await;
            runtime_bob.shutdown().await;
            runtime_charlie.shutdown().await;
            alice_inbox.shutdown().await;
            bob_inbox.shutdown().await;
            charlie_inbox.shutdown().await;
            joe_inbox.shutdown().await;
            std::process::exit(1);
        }
    }

    runtime_alice.shutdown().await;
    runtime_bob.shutdown().await;
    runtime_charlie.shutdown().await;
    alice_inbox.shutdown().await;
    bob_inbox.shutdown().await;
    charlie_inbox.shutdown().await;
    joe_inbox.shutdown().await;
    Ok(())
}

fn router_config(
    local_address: &str,
    bind: &str,
    seed_peers: &[&str],
) -> Result<PeerConfig, Box<dyn std::error::Error>> {
    let mut cfg = PeerConfig::from_toml_str(cmr_peer::config::EXAMPLE_CONFIG_TOML)?;
    cfg.local_address = local_address.to_owned();
    cfg.listen.http = Some(HttpListenConfig {
        bind: bind.to_owned(),
        path: "/cmr".to_owned(),
    });
    cfg.listen.https = None;
    cfg.listen.udp = None;
    cfg.listen.smtp = None;
    cfg.dashboard.enabled = false;
    cfg.ambient.seed_fanout = seed_peers.len().max(1);
    cfg.ambient.seed_peers = seed_peers.iter().map(|p| (*p).to_owned()).collect();

    let mut policy = cfg.effective_policy();
    policy.spam.min_intrinsic_dependence = 0.0;
    policy.spam.max_match_distance = 1_000_000.0;
    policy.trust.require_signatures_from_known_peers = false;
    policy.trust.reject_signed_without_known_key = false;
    policy.trust.allow_unsigned_from_unknown_peers = true;
    cfg.policy = Some(policy);
    Ok(cfg)
}

async fn wait_for_body_contains(
    inbox: &mut HttpInbox,
    needle: &str,
    timeout: Duration,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let recv = tokio::time::timeout(Duration::from_millis(250), inbox.recv()).await;
        let Ok(Some(message)) = recv else {
            continue;
        };
        let body = String::from_utf8_lossy(&message.message.body).to_string();
        println!("inbox received body: {body}");
        if body.contains(needle) {
            return Some(body);
        }
    }
    None
}
