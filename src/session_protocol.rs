//! The h2 attested-session wire protocol -- framing, AAD, and the ECDH/AEAD
//! primitives -- shared between every Rust party that speaks it on the
//! server side: attested_session.rs (in this package's own
//! `attester-service` binary) and src/bin/session_master.rs (the Azure
//! Confidential ACI backend, a separate binary built with
//! `--features aci-attestation` -- see that file's own module doc
//! comment). One implementation, not several independently written ones
//! -- this session already found a real Rust/Python AAD mismatch in this
//! exact protocol once, caught only by an actual loopback test; two
//! *Rust* copies of the same wire format carry the identical risk of
//! drifting apart, for no reason, since nothing about the framing or
//! crypto differs.
//!
//! See agent.py's own H2_SESSION_DOMAIN_SEPARATOR/_h2_session_binding_hash()/
//! start_h2_attested_session() for the client half every function here
//! has to agree with byte-for-byte.
//!
//! The h2_read_frame()/h2_write_frame() pair below carry this exact same
//! frame format (4-byte big-endian length prefix + payload) over an h2
//! stream's DATA frames instead of a raw TcpStream -- read_frame()/
//! write_frame()'s own TCP-specific versions can't be reused directly
//! (h2's SendStream/RecvStream don't implement AsyncRead/AsyncWrite),
//! but the two need to agree on the identical byte-level framing, since
//! session_master.rs's own client leg and callback.rs's server leg are
//! opposite ends of the same connection.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use bytes::Bytes;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Same string as agent.py's H2_SESSION_DOMAIN_SEPARATOR -- has to match
/// byte-for-byte or the binding hash and the derived session key never
/// agree with the client's own. Bump the "v1" on both sides together if
/// this handshake's message shape ever changes incompatibly.
pub const DOMAIN: &[u8] = b"directionally-h2-attested-session-v1";
pub const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// `DOMAIN + b"|" + <direction>` -- matches agent.py's own
/// h2_session_send()/h2_session_recv() exactly (`H2_SESSION_DOMAIN_SEPARATOR
/// + b"|" + aad`), not just the bare direction tag: get this wrong and
/// every frame fails AEAD authentication despite the session key itself
/// being correct -- confirmed the hard way against a real loopback run
/// before this existed as shared code.
pub fn client_to_server_aad() -> Vec<u8> {
    [DOMAIN, b"|client-to-server"].concat()
}

pub fn server_to_client_aad() -> Vec<u8> {
    [DOMAIN, b"|server-to-client"].concat()
}

pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, SessionError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), SessionError> {
    stream.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

/// SHA-256(DOMAIN || client_public_key) -- what the attestation document
/// must bind to, and what the client independently recomputes to check
/// this session's own server_hello isn't attesting a substituted key.
pub fn binding_hash(client_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(client_public_key);
    hasher.finalize().into()
}

/// ECDH(ephemeral_secret, client_public_key) -> HKDF-SHA256(info=DOMAIN)
/// (scalar * point, take the x-coordinate, HKDF-expand it) -- the same
/// construction crypto.rs's own (now-removed) ecies_encrypt() used, kept
/// independently here since session_master.rs, a separate binary, can't
/// depend on that crate-local module.
pub fn derive_session_key(ephemeral_secret: &SecretKey, client_public_key: &PublicKey) -> [u8; 32] {
    let scalar = ephemeral_secret.to_nonzero_scalar();
    let shared_point = (*client_public_key.as_affine() * *scalar).to_affine();
    let shared_bytes = shared_point.x();

    let hkdf = hkdf::Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut key = [0u8; 32];
    // Never fails for a 32-byte output -- HKDF-SHA256's max is 255*32
    // bytes, this asks for one block.
    hkdf.expand(DOMAIN, &mut key).expect("HKDF-SHA256 expand");
    key
}

pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("AES-256-GCM encrypt");
    let mut framed = nonce_bytes.to_vec();
    framed.extend_from_slice(&ciphertext);
    framed
}

pub fn open(key: &[u8; 32], framed: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
    if framed.len() < NONCE_LEN {
        return Err(SessionError::Protocol("frame too short to hold a nonce".to_string()));
    }
    let (nonce_bytes, ciphertext) = framed.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce_bytes), Payload { msg: ciphertext, aad })
        .map_err(|_| SessionError::Protocol("AEAD authentication failed".to_string()))
}

// -- callback h2c framing ----------------------------------------------

/// How session_master.rs's own client leg and callback.rs's server leg
/// correlate one inbound h2c stream to the specific launch that's
/// waiting for it -- a fresh token minted per launch, sent as a plain
/// HTTP header on the one request this protocol ever makes, checked
/// before that stream is ever bridged to a client connection.
pub const CALLBACK_TOKEN_HEADER: &str = "x-callback-token";
pub const CALLBACK_PATH: &str = "/callback";

/// A CALLBACK_TOKEN_HEADER value meaning "I have no specific pending
/// registration to fulfill -- add me to the shared-worker queue instead"
/// rather than a real, opaquely-random token minted for one particular
/// launch. session_master.rs's own aci_callback_handler() sends
/// `SHARED_QUEUE_TOKEN_PREFIX` + its own ACI_GROUP_NAME + ":" + its own
/// worker_execution_options() as the token on this connection
/// (dial_callback() itself needs no change at all -- a token is a token
/// as far as that function or the HTTP framing are concerned); the group
/// name rides along because session_master.rs is the only party that
/// knows its own container group's name at this point and
/// aci_executor::PooledWorker needs it to tear the group down later
/// (a real ARM DELETE) once this entry is finally discarded, matched or
/// not -- see that type's own doc comment. worker_options itself must
/// never contain a literal ':' for this split to stay unambiguous
/// (WORKER_EXECUTION_OPTIONS is comma-separated key=value tokens by
/// convention, never colon-delimited).
///
/// callback.rs's own handle_callback_stream() checks for this
/// prefix before ever looking the token up in CallbackState's own
/// pending map, and routes it into attested_session.rs's own
/// SharedWorkerPool instead. Lives here, not in either binary alone,
/// because both sides have to agree on the exact same string. No real
/// token is ever a valid group-name-plus-options string wearing this
/// same prefix by accident -- tokens are uuid::Uuid::new_v4() elsewhere,
/// which can never start with an ASCII "shared:".
pub const SHARED_QUEUE_TOKEN_PREFIX: &str = "shared:";

/// Writes one frame (4-byte big-endian length prefix + payload, exactly
/// read_frame()/write_frame()'s own TCP framing above) as a single h2
/// DATA frame. `send_data()` is sync -- it enqueues onto the stream's
/// own send buffer, which the connection task (spawned by whichever
/// caller drove the h2 handshake) drains onto the wire under h2's own
/// flow control -- so this doesn't manually reserve/await send capacity
/// the way a very large payload would need to; every frame this
/// protocol ever sends is a small JSON/binary blob, not a bulk
/// transfer, so the simplification is deliberate, not an oversight.
pub fn h2_write_frame(
    send: &mut h2::SendStream<Bytes>,
    payload: &[u8],
    end_stream: bool,
) -> Result<(), SessionError> {
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    send.send_data(Bytes::from(framed), end_stream)
        .map_err(|e| SessionError::Protocol(format!("h2 send_data failed: {e}")))
}

/// Reads one frame back out of a RecvStream, accumulating across as many
/// DATA chunks as it takes to see the full 4-byte length prefix plus
/// that many payload bytes -- an h2 peer is free to fragment one logical
/// write into multiple DATA frames, so this can't assume one chunk is
/// one frame the way a naive read would. Works identically for a
/// client-side ResponseFuture's body or a server-side Request's body --
/// h2 uses the same RecvStream type for both directions.
pub async fn h2_read_frame(body: &mut h2::RecvStream) -> Result<Vec<u8>, SessionError> {
    let mut flow_control = body.flow_control().clone();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if buf.len() >= 4 {
            let len = u32::from_be_bytes(buf[0..4].try_into().expect("checked len >= 4 above")) as usize;
            if buf.len() >= 4 + len {
                return Ok(buf[4..4 + len].to_vec());
            }
        }
        match body.data().await {
            Some(Ok(chunk)) => {
                let consumed = chunk.len();
                buf.extend_from_slice(&chunk);
                let _ = flow_control.release_capacity(consumed);
            }
            Some(Err(e)) => return Err(SessionError::Protocol(format!("h2 recv error: {e}"))),
            None => return Err(SessionError::Protocol("h2 stream ended before a full frame arrived".to_string())),
        }
    }
}
