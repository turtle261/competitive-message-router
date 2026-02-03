//! Router core: validation, security policy, cache matching, and forwarding.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use num_bigint::BigUint;
use rand::RngCore;
use thiserror::Error;

use crate::key_exchange::{KeyExchangeError, KeyExchangeMessage, mod_pow, parse_key_exchange};
use crate::policy::RoutingPolicy;
use crate::protocol::{
    CmrMessage, CmrTimestamp, MessageId, ParseContext, ParseError, Signature, TransportKind,
    parse_message,
};

/// Compression-oracle failures.
#[derive(Debug, Error)]
pub enum CompressionError {
    /// Backing compressor unavailable.
    #[error("compressor unavailable: {0}")]
    Unavailable(String),
    /// Backing compressor returned an error.
    #[error("compressor failure: {0}")]
    Failed(String),
}

/// Compression capability (intentionally abstracted from router process).
pub trait CompressionOracle: Send + Sync {
    /// Symmetric NCD-like distance.
    fn ncd_sym(&self, left: &[u8], right: &[u8]) -> Result<f64, CompressionError>;
    /// Intrinsic dependence.
    fn intrinsic_dependence(&self, data: &[u8], max_order: i64) -> Result<f64, CompressionError>;
    /// Batch NCD, defaulting to repeated scalar calls.
    fn batch_ncd_sym(
        &self,
        target: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<f64>, CompressionError> {
        let mut out = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            out.push(self.ncd_sym(target, candidate)?);
        }
        Ok(out)
    }
}

#[derive(Clone, Debug)]
struct CacheEntry {
    key: String,
    message: CmrMessage,
    body_tokens: Vec<String>,
    encoded_size: usize,
}

#[derive(Debug)]
struct MessageCache {
    entries: HashMap<String, CacheEntry>,
    order: VecDeque<String>,
    id_index: HashMap<String, String>,
    token_index: HashMap<String, HashSet<String>>,
    total_bytes: usize,
    max_messages: usize,
    max_bytes: usize,
}

impl MessageCache {
    fn new(max_messages: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            id_index: HashMap::new(),
            token_index: HashMap::new(),
            total_bytes: 0,
            max_messages,
            max_bytes,
        }
    }

    fn contains_any_id(&self, message: &CmrMessage) -> bool {
        message
            .header
            .iter()
            .map(MessageId::to_string)
            .any(|id| self.id_index.contains_key(&id))
    }

    fn insert(&mut self, message: CmrMessage) {
        let key = cache_key(&message);
        if self.entries.contains_key(&key) {
            return;
        }
        let encoded_size = message.encoded_len();
        let body_tokens = tokenize_for_index(&message.body);
        let entry = CacheEntry {
            key: key.clone(),
            message,
            body_tokens,
            encoded_size,
        };
        self.total_bytes = self.total_bytes.saturating_add(encoded_size);
        self.order.push_back(key.clone());
        for id in &entry.message.header {
            self.id_index.insert(id.to_string(), key.clone());
        }
        for token in &entry.body_tokens {
            self.token_index
                .entry(token.clone())
                .or_default()
                .insert(key.clone());
        }
        self.entries.insert(key, entry);
        self.evict_as_needed();
    }

    fn evict_as_needed(&mut self) {
        while self.entries.len() > self.max_messages || self.total_bytes > self.max_bytes {
            let Some(key) = self.order.pop_front() else {
                break;
            };
            let Some(entry) = self.entries.remove(&key) else {
                continue;
            };
            self.total_bytes = self.total_bytes.saturating_sub(entry.encoded_size);
            for id in &entry.message.header {
                self.id_index.remove(&id.to_string());
            }
            for token in &entry.body_tokens {
                if let Some(set) = self.token_index.get_mut(token) {
                    set.remove(&entry.key);
                    if set.is_empty() {
                        self.token_index.remove(token);
                    }
                }
            }
        }
    }

    fn candidate_keys(&self, body: &[u8], max_candidates: usize) -> Vec<String> {
        if self.entries.is_empty() || max_candidates == 0 {
            return Vec::new();
        }
        let tokens = tokenize_for_index(body);
        if tokens.is_empty() {
            return self
                .order
                .iter()
                .rev()
                .take(max_candidates)
                .cloned()
                .collect();
        }
        let mut score = HashMap::<String, u32>::new();
        for token in tokens {
            let Some(keys) = self.token_index.get(&token) else {
                continue;
            };
            for key in keys.iter().take(4096) {
                *score.entry(key.clone()).or_default() += 1;
            }
        }
        if score.is_empty() {
            return self
                .order
                .iter()
                .rev()
                .take(max_candidates)
                .cloned()
                .collect();
        }
        let mut ranked: Vec<(String, u32)> = score.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked
            .into_iter()
            .take(max_candidates)
            .map(|(k, _)| k)
            .collect()
    }
}

#[derive(Clone, Debug)]
struct PeerMetrics {
    reputation: f64,
    inbound_messages: u64,
    inbound_bytes: u64,
    outbound_messages: u64,
    outbound_bytes: u64,
    window: RateWindow,
}

impl Default for PeerMetrics {
    fn default() -> Self {
        Self {
            reputation: 0.0,
            inbound_messages: 0,
            inbound_bytes: 0,
            outbound_messages: 0,
            outbound_bytes: 0,
            window: RateWindow::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct RateWindow {
    started: Instant,
    messages: u32,
    bytes: u64,
}

impl RateWindow {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            messages: 0,
            bytes: 0,
        }
    }

    fn allow_and_record(
        &mut self,
        message_bytes: usize,
        max_messages_per_minute: u32,
        max_bytes_per_minute: u64,
    ) -> bool {
        if self.started.elapsed() >= Duration::from_secs(60) {
            self.started = Instant::now();
            self.messages = 0;
            self.bytes = 0;
        }
        let next_messages = self.messages.saturating_add(1);
        let next_bytes = self
            .bytes
            .saturating_add(u64::try_from(message_bytes).unwrap_or(u64::MAX));
        if next_messages > max_messages_per_minute || next_bytes > max_bytes_per_minute {
            return false;
        }
        self.messages = next_messages;
        self.bytes = next_bytes;
        true
    }
}

#[derive(Clone, Debug)]
struct PendingRsaState {
    n: BigUint,
    d: BigUint,
}

#[derive(Clone, Debug)]
struct PendingDhState {
    p: BigUint,
    a_secret: BigUint,
}

/// Forward reason.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ForwardReason {
    /// Matched incoming -> cached forward.
    IncomingToMatchedHeader,
    /// Matched cached -> incoming header forward.
    MatchedToIncomingHeader,
    /// Key-exchange protocol reply.
    KeyExchangeReply,
}

/// Prepared outbound action.
#[derive(Clone, Debug)]
pub struct ForwardAction {
    /// Recipient peer address.
    pub destination: String,
    /// Wire bytes.
    pub message_bytes: Vec<u8>,
    /// Reason for forwarding.
    pub reason: ForwardReason,
}

/// Processing rejection reason.
#[derive(Debug, Error)]
pub enum ProcessError {
    /// Parse failure.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
    /// Message duplicates cache by ID.
    #[error("duplicate message id in cache")]
    DuplicateMessageId,
    /// Peer throttled by anti-flood controls.
    #[error("peer exceeded flood limits")]
    FloodLimited,
    /// Global throttling triggered.
    #[error("global flood limits exceeded")]
    GlobalFloodLimited,
    /// Peer reputation below threshold.
    #[error("peer reputation below threshold")]
    ReputationTooLow,
    /// Unsigned message violates policy.
    #[error("unsigned message violates trust policy")]
    UnsignedRejected,
    /// Signature cannot be verified.
    #[error("signature verification failed")]
    BadSignature,
    /// Signed message from unknown key violates policy.
    #[error("signed message without known key rejected")]
    SignedWithoutKnownKey,
    /// Message body exceeds policy.
    #[error("message body exceeds content policy")]
    BodyTooLarge,
    /// Binary content blocked.
    #[error("binary content blocked by policy")]
    BinaryContentBlocked,
    /// Executable payload blocked.
    #[error("executable payload blocked by policy")]
    ExecutableBlocked,
    /// Intrinsic-dependence spam check failed.
    #[error("message failed intrinsic dependence spam check")]
    IntrinsicDependenceTooLow,
    /// Compression oracle error.
    #[error("compression oracle error: {0}")]
    Compression(#[from] CompressionError),
    /// Key-exchange parse error.
    #[error("key exchange parse error: {0}")]
    KeyExchange(#[from] KeyExchangeError),
    /// Clear key exchange on insecure channel.
    #[error("clear key exchange requires secure channel")]
    ClearKeyOnInsecureChannel,
    /// Malformed key-exchange state.
    #[error("unexpected key exchange reply without pending state")]
    MissingPendingKeyExchangeState,
}

/// Result of processing one inbound message.
#[derive(Debug)]
pub struct ProcessOutcome {
    /// Whether message was accepted.
    pub accepted: bool,
    /// Drop reason when not accepted.
    pub drop_reason: Option<ProcessError>,
    /// Parsed message if available.
    pub parsed_message: Option<CmrMessage>,
    /// Intrinsic dependence score when computed.
    pub intrinsic_dependence: Option<f64>,
    /// Generated forwarding actions.
    pub forwards: Vec<ForwardAction>,
    /// Number of semantic matches found.
    pub matched_count: usize,
    /// Whether this was a key exchange control message.
    pub key_exchange_control: bool,
}

impl ProcessOutcome {
    fn dropped(reason: ProcessError) -> Self {
        Self {
            accepted: false,
            drop_reason: Some(reason),
            parsed_message: None,
            intrinsic_dependence: None,
            forwards: Vec::new(),
            matched_count: 0,
            key_exchange_control: false,
        }
    }

    fn accepted(message: CmrMessage) -> Self {
        Self {
            accepted: true,
            drop_reason: None,
            parsed_message: Some(message),
            intrinsic_dependence: None,
            forwards: Vec::new(),
            matched_count: 0,
            key_exchange_control: false,
        }
    }
}

/// In-memory CMR router.
pub struct Router<O: CompressionOracle> {
    local_address: String,
    policy: RoutingPolicy,
    oracle: O,
    cache: MessageCache,
    peers: HashMap<String, PeerMetrics>,
    global_window: RateWindow,
    shared_keys: HashMap<String, Vec<u8>>,
    pending_rsa: HashMap<String, PendingRsaState>,
    pending_dh: HashMap<String, PendingDhState>,
    forward_counter: u64,
}

impl<O: CompressionOracle> Router<O> {
    /// Creates a router instance.
    #[must_use]
    pub fn new(local_address: String, policy: RoutingPolicy, oracle: O) -> Self {
        Self {
            local_address,
            cache: MessageCache::new(policy.cache_max_messages, policy.cache_max_bytes),
            policy,
            oracle,
            peers: HashMap::new(),
            global_window: RateWindow::new(),
            shared_keys: HashMap::new(),
            pending_rsa: HashMap::new(),
            pending_dh: HashMap::new(),
            forward_counter: 0,
        }
    }

    /// Registers a pairwise shared key.
    pub fn set_shared_key(&mut self, peer: impl Into<String>, key: Vec<u8>) {
        self.shared_keys.insert(peer.into(), key);
    }

    /// Gets known shared key.
    #[must_use]
    pub fn shared_key(&self, peer: &str) -> Option<&[u8]> {
        self.shared_keys.get(peer).map(Vec::as_slice)
    }

    /// Stores pending RSA initiator state for incoming replies.
    pub fn register_pending_rsa_state(&mut self, peer: impl Into<String>, n: BigUint, d: BigUint) {
        self.pending_rsa
            .insert(peer.into(), PendingRsaState { n, d });
    }

    /// Stores pending DH initiator state for incoming replies.
    pub fn register_pending_dh_state(
        &mut self,
        peer: impl Into<String>,
        p: BigUint,
        a_secret: BigUint,
    ) {
        self.pending_dh
            .insert(peer.into(), PendingDhState { p, a_secret });
    }

    /// Processes one inbound message.
    #[must_use]
    pub fn process_incoming(
        &mut self,
        raw_message: &[u8],
        transport: TransportKind,
        now: CmrTimestamp,
    ) -> ProcessOutcome {
        let parse_ctx = ParseContext {
            now: now.clone(),
            recipient_address: Some(self.local_address.as_str()),
            max_message_bytes: self.policy.content.max_message_bytes,
            max_header_ids: self.policy.content.max_header_ids,
            allow_legacy_v1_without_prefix: self
                .policy
                .content
                .allow_legacy_signature_without_version_prefix,
        };

        let parsed = match parse_message(raw_message, &parse_ctx) {
            Ok(m) => m,
            Err(err) => return ProcessOutcome::dropped(ProcessError::Parse(err)),
        };

        if parsed.body.len() > self.policy.content.max_body_bytes {
            return self.drop_for_peer(&parsed, ProcessError::BodyTooLarge, -2.0);
        }

        let sender = parsed.immediate_sender().to_owned();
        if !self.check_global_rate(raw_message.len()) {
            return self.drop_for_peer(&parsed, ProcessError::GlobalFloodLimited, -1.5);
        }
        if !self.check_peer_rate(&sender, raw_message.len()) {
            return self.drop_for_peer(&parsed, ProcessError::FloodLimited, -2.0);
        }
        if self.peer_reputation(&sender) < self.policy.trust.min_reputation_score {
            return self.drop_for_peer(&parsed, ProcessError::ReputationTooLow, -0.5);
        }
        if let Err(err) = self.validate_signature_policy(&parsed, &sender) {
            return self.drop_for_peer(&parsed, err, -4.0);
        }
        if self.cache.contains_any_id(&parsed) {
            return self.drop_for_peer(&parsed, ProcessError::DuplicateMessageId, -0.1);
        }
        if !self.policy.content.allow_binary_payloads && is_probably_binary(&parsed.body) {
            return self.drop_for_peer(&parsed, ProcessError::BinaryContentBlocked, -0.4);
        }
        if self.policy.content.block_executable_magic && looks_like_executable(&parsed.body) {
            return self.drop_for_peer(&parsed, ProcessError::ExecutableBlocked, -2.5);
        }

        match self.handle_key_exchange_control(&parsed, &sender, &transport, &now) {
            Ok(Some(forwards)) => {
                self.adjust_peer_reputation(&sender, 1.5);
                self.record_peer_inbound(&sender, raw_message.len());
                return ProcessOutcome {
                    accepted: true,
                    drop_reason: None,
                    parsed_message: Some(parsed),
                    intrinsic_dependence: None,
                    forwards,
                    matched_count: 0,
                    key_exchange_control: true,
                };
            }
            Ok(None) => {}
            Err(err) => return self.drop_for_peer(&parsed, err, -3.0),
        }

        let id_score = match self
            .oracle
            .intrinsic_dependence(&parsed.body, self.policy.spam.intrinsic_dependence_order)
        {
            Ok(score) => score,
            Err(err) => {
                return self.drop_for_peer(
                    &parsed,
                    ProcessError::Compression(err),
                    if self.policy.security_level == crate::policy::SecurityLevel::Trusted {
                        -0.2
                    } else {
                        -1.0
                    },
                );
            }
        };
        if id_score < self.policy.spam.min_intrinsic_dependence {
            return self.drop_for_peer(&parsed, ProcessError::IntrinsicDependenceTooLow, -1.5);
        }

        let matched = match self.match_cached_messages(&parsed) {
            Ok(m) => m,
            Err(err) => return self.drop_for_peer(&parsed, err, -0.5),
        };
        let mut outcome = ProcessOutcome::accepted(parsed.clone());
        outcome.intrinsic_dependence = Some(id_score);
        outcome.matched_count = matched.len();

        self.cache.insert(parsed.clone());
        self.record_peer_inbound(&sender, raw_message.len());
        self.adjust_peer_reputation(&sender, 0.4);

        let forwards = self.build_forwards(&parsed, &matched, &now);
        let mut limited = forwards;
        limited.truncate(self.policy.throughput.max_forward_actions);
        for action in &limited {
            self.record_peer_outbound(&action.destination, action.message_bytes.len());
        }
        outcome.forwards = limited;
        outcome
    }

    fn drop_for_peer(
        &mut self,
        parsed: &CmrMessage,
        reason: ProcessError,
        reputation_delta: f64,
    ) -> ProcessOutcome {
        let sender = parsed.immediate_sender().to_owned();
        self.adjust_peer_reputation(&sender, reputation_delta);
        ProcessOutcome {
            accepted: false,
            drop_reason: Some(reason),
            parsed_message: Some(parsed.clone()),
            intrinsic_dependence: None,
            forwards: Vec::new(),
            matched_count: 0,
            key_exchange_control: false,
        }
    }

    fn check_peer_rate(&mut self, peer: &str, message_bytes: usize) -> bool {
        let metrics = self.peers.entry(peer.to_owned()).or_default();
        metrics.window.allow_and_record(
            message_bytes,
            self.policy.throughput.per_peer_messages_per_minute,
            self.policy.throughput.per_peer_bytes_per_minute,
        )
    }

    fn check_global_rate(&mut self, message_bytes: usize) -> bool {
        self.global_window.allow_and_record(
            message_bytes,
            self.policy.throughput.global_messages_per_minute,
            self.policy.throughput.global_bytes_per_minute,
        )
    }

    fn peer_reputation(&self, peer: &str) -> f64 {
        self.peers.get(peer).map_or(0.0, |p| p.reputation)
    }

    fn adjust_peer_reputation(&mut self, peer: &str, delta: f64) {
        let metrics = self.peers.entry(peer.to_owned()).or_default();
        metrics.reputation = (metrics.reputation + delta).clamp(-100.0, 100.0);
    }

    fn record_peer_inbound(&mut self, peer: &str, bytes: usize) {
        let metrics = self.peers.entry(peer.to_owned()).or_default();
        metrics.inbound_messages = metrics.inbound_messages.saturating_add(1);
        metrics.inbound_bytes = metrics
            .inbound_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn record_peer_outbound(&mut self, peer: &str, bytes: usize) {
        let metrics = self.peers.entry(peer.to_owned()).or_default();
        metrics.outbound_messages = metrics.outbound_messages.saturating_add(1);
        metrics.outbound_bytes = metrics
            .outbound_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn can_forward_to_peer(&self, peer: &str) -> bool {
        let Some(metrics) = self.peers.get(peer) else {
            return true;
        };
        if metrics.inbound_bytes == 0 {
            return metrics.outbound_bytes == 0;
        }
        let ratio = metrics.outbound_bytes as f64 / metrics.inbound_bytes as f64;
        ratio <= self.policy.trust.max_outbound_inbound_ratio
    }

    fn validate_signature_policy(
        &self,
        message: &CmrMessage,
        sender: &str,
    ) -> Result<(), ProcessError> {
        let known_key = self.shared_keys.get(sender);
        match (&message.signature, known_key) {
            (Signature::Unsigned, Some(_))
                if self.policy.trust.require_signatures_from_known_peers =>
            {
                Err(ProcessError::UnsignedRejected)
            }
            (Signature::Unsigned, None) if !self.policy.trust.allow_unsigned_from_unknown_peers => {
                Err(ProcessError::UnsignedRejected)
            }
            (Signature::Sha256(_), None) if self.policy.trust.reject_signed_without_known_key => {
                Err(ProcessError::SignedWithoutKnownKey)
            }
            (Signature::Sha256(_), Some(key)) => {
                if message
                    .signature
                    .verifies(&message.payload_without_signature_line(), Some(key))
                {
                    Ok(())
                } else {
                    Err(ProcessError::BadSignature)
                }
            }
            _ => Ok(()),
        }
    }

    fn handle_key_exchange_control(
        &mut self,
        message: &CmrMessage,
        sender: &str,
        transport: &TransportKind,
        now: &CmrTimestamp,
    ) -> Result<Option<Vec<ForwardAction>>, ProcessError> {
        let Some(control) = parse_key_exchange(&message.body)? else {
            return Ok(None);
        };

        let old_key = self.shared_keys.get(sender).cloned();
        match control {
            KeyExchangeMessage::ClearKey { key } => {
                if !transport.is_secure_channel() {
                    return Err(ProcessError::ClearKeyOnInsecureChannel);
                }
                self.shared_keys.insert(sender.to_owned(), key);
                Ok(Some(Vec::new()))
            }
            KeyExchangeMessage::RsaRequest { n, e } => {
                let mut key = [0_u8; 32];
                rand::rng().fill_bytes(&mut key);
                let c = mod_pow(&BigUint::from_bytes_be(&key), &e, &n);
                let reply_body = KeyExchangeMessage::RsaReply { c }.render().into_bytes();
                let reply = self.build_control_reply(sender, reply_body, old_key.as_deref(), now);
                self.shared_keys.insert(sender.to_owned(), key.to_vec());
                Ok(Some(vec![reply]))
            }
            KeyExchangeMessage::RsaReply { c } => {
                let Some(state) = self.pending_rsa.remove(sender) else {
                    return Err(ProcessError::MissingPendingKeyExchangeState);
                };
                let key = mod_pow(&c, &state.d, &state.n).to_bytes_be();
                self.shared_keys.insert(sender.to_owned(), key);
                Ok(Some(Vec::new()))
            }
            KeyExchangeMessage::DhRequest { g, p, a_pub } => {
                let mut b_raw = [0_u8; 32];
                rand::rng().fill_bytes(&mut b_raw);
                let b_secret = BigUint::from_bytes_be(&b_raw);
                let b_pub = mod_pow(&g, &b_secret, &p);
                let shared = mod_pow(&a_pub, &b_secret, &p).to_bytes_be();
                let reply_body = KeyExchangeMessage::DhReply { b_pub }.render().into_bytes();
                let reply = self.build_control_reply(sender, reply_body, old_key.as_deref(), now);
                self.shared_keys.insert(sender.to_owned(), shared);
                Ok(Some(vec![reply]))
            }
            KeyExchangeMessage::DhReply { b_pub } => {
                let Some(state) = self.pending_dh.remove(sender) else {
                    return Err(ProcessError::MissingPendingKeyExchangeState);
                };
                let shared = mod_pow(&b_pub, &state.a_secret, &state.p).to_bytes_be();
                self.shared_keys.insert(sender.to_owned(), shared);
                Ok(Some(Vec::new()))
            }
        }
    }

    fn build_control_reply(
        &mut self,
        destination: &str,
        body: Vec<u8>,
        signing_key: Option<&[u8]>,
        now: &CmrTimestamp,
    ) -> ForwardAction {
        let mut msg = CmrMessage {
            signature: Signature::Unsigned,
            header: vec![MessageId {
                timestamp: self.next_forward_timestamp(now),
                address: self.local_address.clone(),
            }],
            body,
        };
        if let Some(key) = signing_key {
            msg.sign_with_key(key);
        }
        ForwardAction {
            destination: destination.to_owned(),
            message_bytes: msg.to_bytes(),
            reason: ForwardReason::KeyExchangeReply,
        }
    }

    fn match_cached_messages(
        &self,
        incoming: &CmrMessage,
    ) -> Result<Vec<CmrMessage>, ProcessError> {
        let candidate_keys = self
            .cache
            .candidate_keys(&incoming.body, self.policy.throughput.max_match_candidates);
        if candidate_keys.is_empty() {
            return Ok(Vec::new());
        }
        let candidates: Vec<&CacheEntry> = candidate_keys
            .iter()
            .filter_map(|k| self.cache.entries.get(k))
            .collect();
        let payloads: Vec<Vec<u8>> = candidates
            .iter()
            .map(|entry| entry.message.body.clone())
            .collect();
        let distances = self
            .oracle
            .batch_ncd_sym(&incoming.body, &payloads)
            .map_err(ProcessError::Compression)?;

        let matched = candidates
            .into_iter()
            .zip(distances)
            .filter(|(_, distance)| *distance <= self.policy.spam.max_match_distance)
            .map(|(entry, _)| entry.message.clone())
            .collect();
        Ok(matched)
    }

    fn build_forwards(
        &mut self,
        incoming: &CmrMessage,
        matched: &[CmrMessage],
        now: &CmrTimestamp,
    ) -> Vec<ForwardAction> {
        let incoming_addresses = header_address_set(incoming);
        let mut out = Vec::<ForwardAction>::new();
        let mut seen = HashSet::<(String, String, ForwardReason)>::new();

        for cached in matched {
            let cached_addresses = header_address_set(cached);

            for destination in &cached_addresses {
                if destination == &self.local_address || incoming_addresses.contains(destination) {
                    continue;
                }
                if !self.can_forward_to_peer(destination) {
                    continue;
                }
                let dedupe = (
                    destination.clone(),
                    cache_key(incoming),
                    ForwardReason::IncomingToMatchedHeader,
                );
                if seen.insert(dedupe) {
                    out.push(self.wrap_and_forward(
                        incoming,
                        destination,
                        now,
                        ForwardReason::IncomingToMatchedHeader,
                    ));
                }
            }
            for destination in &incoming_addresses {
                if destination == &self.local_address || cached_addresses.contains(destination) {
                    continue;
                }
                if !self.can_forward_to_peer(destination) {
                    continue;
                }
                let dedupe = (
                    destination.clone(),
                    cache_key(cached),
                    ForwardReason::MatchedToIncomingHeader,
                );
                if seen.insert(dedupe) {
                    out.push(self.wrap_and_forward(
                        cached,
                        destination,
                        now,
                        ForwardReason::MatchedToIncomingHeader,
                    ));
                }
            }
        }
        out
    }

    fn wrap_and_forward(
        &mut self,
        message: &CmrMessage,
        destination: &str,
        now: &CmrTimestamp,
        reason: ForwardReason,
    ) -> ForwardAction {
        let mut forwarded = message.clone();
        forwarded.make_unsigned();
        forwarded.prepend_hop(MessageId {
            timestamp: self.next_forward_timestamp(now),
            address: self.local_address.clone(),
        });
        if let Some(key) = self.shared_keys.get(destination) {
            forwarded.sign_with_key(key);
        }
        ForwardAction {
            destination: destination.to_owned(),
            message_bytes: forwarded.to_bytes(),
            reason,
        }
    }

    fn next_forward_timestamp(&mut self, now: &CmrTimestamp) -> CmrTimestamp {
        self.forward_counter = self.forward_counter.saturating_add(1);
        let fraction = format!("{:09}", self.forward_counter % 1_000_000_000);
        now.clone().with_fraction(fraction)
    }
}

fn cache_key(message: &CmrMessage) -> String {
    message
        .origin_id()
        .map_or_else(|| message.header[0].to_string(), MessageId::to_string)
}

fn header_address_set(message: &CmrMessage) -> HashSet<String> {
    message
        .header
        .iter()
        .map(|id| id.address.clone())
        .collect::<HashSet<_>>()
}

fn tokenize_for_index(body: &[u8]) -> Vec<String> {
    let mut out = HashSet::<String>::new();
    let mut current = Vec::<u8>::new();
    for &b in body {
        if b.is_ascii_alphanumeric() {
            if current.len() < 48 {
                current.push(b.to_ascii_lowercase());
            }
        } else {
            if current.len() >= 3 {
                let token = String::from_utf8_lossy(&current).to_string();
                out.insert(token);
            }
            current.clear();
        }
        if out.len() >= 128 {
            break;
        }
    }
    if current.len() >= 3 {
        let token = String::from_utf8_lossy(&current).to_string();
        out.insert(token);
    }
    out.into_iter().collect()
}

fn is_probably_binary(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let non_text = body
        .iter()
        .copied()
        .filter(|b| !matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E))
        .count();
    non_text * 10 > body.len() * 3
}

fn looks_like_executable(body: &[u8]) -> bool {
    body.starts_with(b"\x7fELF")
        || body.starts_with(b"MZ")
        || body.starts_with(b"\xfe\xed\xfa\xce")
        || body.starts_with(b"\xce\xfa\xed\xfe")
        || body.starts_with(b"\xcf\xfa\xed\xfe")
        || body.starts_with(b"\xfe\xed\xfa\xcf")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubOracle;

    impl CompressionOracle for StubOracle {
        fn ncd_sym(&self, _left: &[u8], _right: &[u8]) -> Result<f64, CompressionError> {
            Ok(0.4)
        }

        fn intrinsic_dependence(
            &self,
            _data: &[u8],
            _max_order: i64,
        ) -> Result<f64, CompressionError> {
            Ok(0.5)
        }
    }

    fn now() -> CmrTimestamp {
        CmrTimestamp::parse("2030/01/01 00:00:10").expect("ts")
    }

    #[test]
    fn accepts_minimal_message() {
        let policy = RoutingPolicy::default();
        let mut router = Router::new("http://bob".to_owned(), policy, StubOracle);
        let raw = b"0\r\n2029/12/31 23:59:59 http://alice\r\n\r\n5\r\nhello";
        let outcome = router.process_incoming(raw, TransportKind::Http, now());
        assert!(outcome.accepted);
        assert!(outcome.drop_reason.is_none());
    }

    #[test]
    fn rejects_duplicate_id() {
        let policy = RoutingPolicy::default();
        let mut router = Router::new("http://bob".to_owned(), policy, StubOracle);
        let raw = b"0\r\n2029/12/31 23:59:59 http://alice\r\n\r\n5\r\nhello";
        let first = router.process_incoming(raw, TransportKind::Http, now());
        assert!(first.accepted);
        let second = router.process_incoming(raw, TransportKind::Http, now());
        assert!(!second.accepted);
        assert!(matches!(
            second.drop_reason,
            Some(ProcessError::DuplicateMessageId)
        ));
    }
}
