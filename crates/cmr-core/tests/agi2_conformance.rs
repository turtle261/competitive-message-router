use cmr_core::policy::RoutingPolicy;
use cmr_core::protocol::{
    CmrMessage, CmrTimestamp, MessageId, ParseContext, Signature, TransportKind, parse_message,
};
use cmr_core::router::{CompressionError, CompressionOracle, ForwardReason, Router};
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn ts(value: &str) -> CmrTimestamp {
    CmrTimestamp::parse(value).expect("timestamp")
}

fn permissive_policy() -> RoutingPolicy {
    let mut policy = RoutingPolicy::default();
    policy.spam.min_intrinsic_dependence = 0.0;
    policy.trust.require_signatures_from_known_peers = false;
    policy.trust.reject_signed_without_known_key = false;
    policy.trust.allow_unsigned_from_unknown_peers = true;
    policy
}

fn message_with_sender(
    sender: &str,
    body: &[u8],
    signature_key: Option<&[u8]>,
    timestamp: &str,
) -> Vec<u8> {
    let mut message = CmrMessage {
        signature: Signature::Unsigned,
        header: vec![MessageId {
            timestamp: ts(timestamp),
            address: sender.to_owned(),
        }],
        body: body.to_vec(),
    };
    if let Some(key) = signature_key {
        message.sign_with_key(key);
    }
    message.to_bytes()
}

fn message_with_sender_and_prior_hop(
    sender: &str,
    prior_hop: &str,
    body: &[u8],
    sender_ts: &str,
    prior_ts: &str,
) -> Vec<u8> {
    let message = CmrMessage {
        signature: Signature::Unsigned,
        header: vec![
            MessageId {
                timestamp: ts(sender_ts),
                address: sender.to_owned(),
            },
            MessageId {
                timestamp: ts(prior_ts),
                address: prior_hop.to_owned(),
            },
        ],
        body: body.to_vec(),
    };
    message.to_bytes()
}

#[derive(Clone, Copy)]
struct MarkerOracle;

impl CompressionOracle for MarkerOracle {
    fn compression_distance(&self, _left: &[u8], right: &[u8]) -> Result<f64, CompressionError> {
        let text = String::from_utf8_lossy(right).to_ascii_lowercase();
        if text.contains("cmr:near") {
            return Ok(0.10);
        }
        if text.contains("cmr:mid") {
            return Ok(0.20);
        }
        Ok(10.0)
    }

    fn intrinsic_dependence(&self, _data: &[u8], _max_order: i64) -> Result<f64, CompressionError> {
        Ok(0.95)
    }

    fn batch_compression_distance(
        &self,
        target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        candidates
            .iter()
            .map(|candidate| self.compression_distance(target, candidate))
            .collect()
    }
}

#[test]
fn appendix_a2_signature_v1_is_hmac_sha256_of_payload() {
    let key = b"foo";
    let mut message = CmrMessage {
        signature: Signature::Unsigned,
        header: vec![MessageId {
            timestamp: ts("2030/01/01 00:00:01"),
            address: "http://alice/".to_owned(),
        }],
        body: b"hello".to_vec(),
    };
    let payload = message.payload_without_signature_line();
    message.sign_with_key(key);

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac");
    mac.update(&payload);
    let expected = format!("1{:x}", mac.finalize().into_bytes());
    assert_eq!(message.signature.line_without_crlf(), expected);
}

#[test]
fn appendix_a3_peer_corpus_match_routes_only_individually_matched_messages() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    let mut router = Router::new("http://local/".to_owned(), policy, MarkerOracle);

    let near = message_with_sender_and_prior_hop(
        "http://peer/",
        "http://dest-near/",
        b"cmr:near",
        "2029/12/31 23:59:59",
        "2029/12/31 23:59:58",
    );
    assert!(
        router
            .process_incoming(&near, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );
    let far = message_with_sender_and_prior_hop(
        "http://peer/",
        "http://dest-far/",
        b"cmr:far",
        "2029/12/31 23:59:57",
        "2029/12/31 23:59:56",
    );
    assert!(
        router
            .process_incoming(&far, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender("http://origin/", b"question", None, "2029/12/31 23:59:55");
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert_eq!(out.matched_count, 1);
    assert!(
        out.forwards
            .iter()
            .any(|forward| forward.destination == "http://dest-near/")
    );
    assert!(
        !out.forwards
            .iter()
            .any(|forward| forward.destination == "http://dest-far/")
    );
}

#[test]
fn appendix_a3_multiple_messages_from_one_peer_can_all_match() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    let mut router = Router::new("http://local/".to_owned(), policy, MarkerOracle);

    let near = message_with_sender_and_prior_hop(
        "http://peer/",
        "http://dest-near/",
        b"cmr:near",
        "2029/12/31 23:59:59",
        "2029/12/31 23:59:58",
    );
    let mid = message_with_sender_and_prior_hop(
        "http://peer/",
        "http://dest-mid/",
        b"cmr:mid",
        "2029/12/31 23:59:57",
        "2029/12/31 23:59:56",
    );
    assert!(
        router
            .process_incoming(&near, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );
    assert!(
        router
            .process_incoming(&mid, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender("http://origin/", b"question", None, "2029/12/31 23:59:55");
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert_eq!(out.matched_count, 2);
    assert!(
        out.forwards
            .iter()
            .any(|forward| forward.destination == "http://dest-near/")
    );
    assert!(
        out.forwards
            .iter()
            .any(|forward| forward.destination == "http://dest-mid/")
    );
}

#[test]
fn appendix_a3_forwards_rewrap_original_message_with_new_top_hop() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.5;
    policy.trust.max_outbound_inbound_ratio = 10.0;
    let mut router = Router::new("http://local".to_owned(), policy, MarkerOracle);

    let seed = message_with_sender_and_prior_hop(
        "http://peer",
        "http://sink",
        b"cmr:near",
        "2029/12/31 23:59:59",
        "2029/12/31 23:59:58",
    );
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender("http://origin", b"question", None, "2029/12/31 23:59:57");
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    let forward = out
        .forwards
        .iter()
        .find(|item| {
            item.destination == "http://sink"
                && item.reason == ForwardReason::MatchedForwardIncoming
        })
        .expect("expected forward to sink");
    let parsed = parse_message(
        &forward.message_bytes,
        &ParseContext::secure(ts("2030/01/01 00:00:11"), Some("http://sink")),
    )
    .expect("forward parses");
    assert_eq!(parsed.header[0].address, "http://local");
    assert_eq!(parsed.header[1].address, "http://origin");
    assert_eq!(parsed.body, b"question");
}

#[test]
fn appendix_a3_cache_may_delete_when_space_needed() {
    let mut policy = permissive_policy();
    policy.cache_max_messages = 2;
    policy.cache_max_bytes = 256;
    let mut router = Router::new("http://local".to_owned(), policy, MarkerOracle);

    let m1 = message_with_sender("http://a", b"a", None, "2029/12/31 23:59:59");
    let m2 = message_with_sender("http://b", b"b", None, "2029/12/31 23:59:58");
    let m3 = message_with_sender("http://c", b"c", None, "2029/12/31 23:59:57");

    assert!(
        router
            .process_incoming(&m1, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );
    assert!(
        router
            .process_incoming(&m2, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );
    assert!(
        router
            .process_incoming(&m3, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let stats = router.cache_stats();
    assert_eq!(stats.entry_count, 2);
    assert!(stats.total_evictions >= 1);
}

#[test]
fn appendix_a3_raw_threshold_remains_forwarding_gate() {
    let mut policy = permissive_policy();
    policy.spam.max_match_distance = 0.0;
    let mut router = Router::new("http://local/".to_owned(), policy, MarkerOracle);

    let seed = message_with_sender_and_prior_hop(
        "http://peer/",
        "http://dest-near/",
        b"cmr:near",
        "2029/12/31 23:59:59",
        "2029/12/31 23:59:58",
    );
    assert!(
        router
            .process_incoming(&seed, TransportKind::Http, ts("2030/01/01 00:00:10"))
            .accepted
    );

    let incoming = message_with_sender("http://origin/", b"question", None, "2029/12/31 23:59:55");
    let out = router.process_incoming(&incoming, TransportKind::Http, ts("2030/01/01 00:00:10"));
    assert!(out.accepted);
    assert_eq!(out.matched_count, 0);
    assert!(out.forwards.is_empty());
}
