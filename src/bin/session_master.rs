//! The "master" binary for the h2 attested-session protocol -- the Azure
//! Confidential ACI backend, built with `--features aci-attestation`
//! (aci/Dockerfile; see Cargo.toml's own comment on that feature). Dials
//! back out to attested_session.rs's callback listener, presents a
//! token, and does the real SEV-SNP/MAA handshake itself (get_maa_token()
//! and friends) as the first thing it sends back over that connection --
//! attested_session.rs relays that real evidence to the actual client as
//! its own server_hello, attestation happens in this container, never
//! faked or substituted by attester-service itself.
//!
//! An AWS Lambda backend used to be built from this same source (no
//! feature, lambda/Dockerfile) -- removed entirely, along with
//! lambda_callback.rs's own Lambda-invoke code and every Docker-execution
//! REST endpoint api.rs used to serve. Building without
//! `--features aci-attestation` is still possible (main()'s own
//! `#[cfg(not(...))]` arm just logs and exits) rather than making the
//! feature non-optional, since that would touch Cargo.toml's `sev`
//! dependency and this repo doesn't edit [dependencies] without a
//! `cargo`-regenerated Cargo.lock (no cargo in the sandbox this was
//! written in).
//!
//! This process never binds an inbound port or accepts a connection --
//! it dials *out*, presents a token, runs exactly one session (or, in
//! shared-worker mode, more than one over successive fresh connections --
//! see is_shared_worker()'s own doc comment), then exits. Two earlier
//! designs are retired in favor of this one: a synchronous REST/ECIES
//! flow (aci_executor.rs's old execute()/execute_in_group(), consumed by
//! api.rs's old /execute-aci-encrypted) that called `/v1/attestation`/
//! `/v1/execute` routes this binary never actually served, and this
//! file's own earlier `run_aci_mode()`, which bound a port and waited for
//! the *client* to connect directly to this container's own public IP --
//! never routed through attester-service at all.
//!
//! Whatever launches this container group MUST set `restartPolicy:
//! Never` in its ARM/YAML definition -- confirmed against Microsoft's own
//! docs (container-instances-liveness-probe,
//! container-instances-readiness-probe): `restartPolicy: Always` or
//! `OnFailure` means Azure relaunches the container in place after this
//! process exits, success or failure alike, silently turning "run one
//! session and terminate" into an unbounded restart loop reusing the
//! same container. Not something this binary can set itself -- it's a
//! property of the launch call, not of the image or the process running
//! inside it. The container group profile now needs no `ipAddress`/
//! `ports` at all -- this process only ever dials out.
//!
//! DRAFT. Nothing here has been run against a real Azure Confidential ACI
//! deployment -- no such deployment exists yet (same caveat every other
//! Azure attestation path in this codebase carries). No SKR sidecar
//! either: this process reads the SNP report and platform certs itself
//! (see get_maa_token()'s own doc comment) rather than running that
//! sidecar as a second container and calling its REST API -- built
//! against its real Go source's actual, verified logic (report-data
//! hashing, cert lookup, MAA request shape), not guessed, but genuinely
//! untested against real hardware.
//!
//! ACI build's protocol, over the same callback h2c stream Lambda uses,
//! mirroring attested_session.rs's own client-facing handshake but with
//! attester-service relaying rather than terminating it (via the shared
//! session_protocol module):
//!   1. dial ACI_CALLBACK_ADDR, present ACI_CALLBACK_TOKEN via h2c
//!      dial/handshake/POST CALLBACK_PATH (dial_callback()'s own job)
//!   2. read {client_public_key} off the stream -- attested_session.rs
//!      forwards the real client's own client_hello key here once it has
//!      matched this connection to a pending session
//!   3. fresh ephemeral P-256 keypair
//!   4. client_public_key_hash = session_protocol::binding_hash(...)
//!   5. get a real MAA token bound to that hash -- see get_maa_token()'s
//!      own doc comment for the exact claim this binds to
//!      (steps 3-5 are aci_handshake()'s own job, split out so a failure
//!      anywhere in them can be reported below instead of just dropping
//!      the stream)
//!   6. write {ephemeral_public_key, attestation_document} back over the
//!      stream -- attested_session.rs relays this to the real client as
//!      its own server_hello (attestation_type "azure-aci-maa") only
//!      after verifying it itself. On failure anywhere in steps 2-6
//!      instead: write {type: "error", message} over the same stream
//!      before exiting -- confirmed live that letting the stream just
//!      drop unclosed here surfaces on attested_session.rs's own side as
//!      an opaque h2 "stream no longer needed" (h2's own documented
//!      behavior for an incomplete stream), giving no way to tell a
//!      config problem from an attestation rejection from anything else,
//!      and no way to check this process's own stdout after the fact
//!      since the container is torn down immediately regardless of
//!      outcome
//!   7. derive the session key via session_protocol::derive_session_key()
//!   8. read one AES-256-GCM frame (AAD "client-to-server"), decrypt ->
//!      {mode, code, storage_grant, pattern_delegate}
//!   9. run_worker(): fetch_worker_bundle() resolves and verifies a
//!      content-hash-pinned tarball from CAS -- a self-contained Python
//!      runtime (interpreter, its own dependencies, worker.py/storage.py
//!      themselves, all published from worker-python-runtime, a
//!      separate, public repo) -- extracts it, and execs its own
//!      `runtime` entry point natively inside a bubblewrap sandbox
//!      (unprivileged user/mount/pid namespace confinement -- see that
//!      function's own doc comment), feeding it {mode, code,
//!      storage_grant, pattern_delegate} on stdin the same shape
//!      worker.py's own handle() already expects
//!   10. encrypt the result (AAD "server-to-client"), write it, exit
//!
//! This image itself carries no Python at all, and no baked-in default
//! worker.py/storage.py -- every session fetches and verifies its own
//! runtime tarball by content hash (`worker_bundle` in the request, see
//! fetch_worker_bundle()); a request without one is refused outright.
//! Earlier revisions of this file baked worker.py/storage.py into the
//! image directly (first for a RISC-V-emulation-based sandbox, rvlinux,
//! that needed them in its own read-only guest filesystem at build time;
//! sandlock's native-execution model kept that same baked-in shape after
//! rvlinux was dropped; then a python:3.12-alpine base image with a
//! per-session fetch as an *opt-in* override on top). None of those
//! execution-model constraints still apply, and worker-python-runtime's
//! own README explains why worker.py/storage.py being committed there in
//! the open (rather than kept private) is a deliberate choice, not a
//! leak -- the trust boundary here is "which exact worker_bundle hash is
//! running," verified via MAA/CCE attestation plus the hash itself, not
//! "keep the workload source private."
//!
//! Master/worker split, not a single in-process call: worker.py's own
//! worker.handle() runs submitted -e/repl code by calling eval()/exec()
//! directly in whatever process calls it, with that process's full
//! privilege level. Keeping that a separate, unprivileged, sandboxed OS
//! process (see run_worker()) rather than an in-process
//! call is still the right posture on its own merits -- ordinary
//! privilege separation between "code that handled the session key" and
//! "code that runs submitted input" -- independent of whatever this
//! container's own network topology happens to be.
//!
//! No sidecar-reachability network isolation here (no more
//! block_untrusted_network_access()) -- this design no longer runs an SKR
//! sidecar at all (get_maa_token() below does that work in-process), so
//! there is nothing local worth firewalling off on that account. If a
//! future revision reintroduces any other local-only, unauthenticated
//! endpoint into this container group (IMDS, most plausibly), that call
//! is worth revisiting then, on its own merits -- it was never solely
//! about the sidecar.

#[cfg(feature = "aci-attestation")]
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
#[cfg(feature = "aci-attestation")]
use serde::Deserialize;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::process::Command;

use aci_worker::session_protocol::{
    client_to_server_aad, h2_read_frame, h2_write_frame, open, read_frame, seal,
    server_to_client_aad, write_frame, SessionError, CALLBACK_PATH, CALLBACK_TOKEN_HEADER,
};
#[cfg(feature = "aci-attestation")]
use aci_worker::session_protocol::{binding_hash, derive_session_key, SHARED_QUEUE_TOKEN_PREFIX};
#[cfg(feature = "aci-attestation")]
use p256::{PublicKey, SecretKey};
// Not feature-gated, unlike the aci-attestation-only imports above: these
// three back fetch_worker_bundle(), which run_worker() calls unconditionally
// (run_worker() itself, BWRAP_BIN etc. are all ungated too).
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use sha2::Digest;

// -- config ------------------------------------------------------------

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// Deliberately duplicated from attested-python-execution's own
/// attestation::mock_attestation_enabled(), not depended on: this is the
/// one place this binary needs it, it's a trivial env-var truthy-check
/// with no business-sensitive content, and the two sides only ever need
/// to agree on the *env var name* (ATTESTER_MOCK_ATTESTATION) -- a
/// runtime contract, not shared code, the same way the launched
/// container's own env vars are a contract with aci_executor.rs's own
/// launch() (that repo) without either side importing the other.
fn mock_attestation_enabled() -> bool {
    matches!(
        std::env::var("ATTESTER_MOCK_ATTESTATION").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("True")
    )
}

/// A bare hostname (e.g. `sharedeus.eus.attest.azure.net`), NOT a full
/// URL -- get_maa_token() builds `https://{endpoint}/attest/...` itself.
/// Real footgun confirmed live: attester-service's own (that's the
/// *separate*, private attested-python-execution repo now)
/// `AciExecutorConfig::maa_endpoint` (aci_executor.rs) reads the identically-named
/// `AZURE_ACI_MAA_ENDPOINT` but expects a full URL there instead (used
/// directly as the JWKS-fetch/issuer base, never `format!()`-assembled).
/// Infra currently sets two different values under the same env var name
/// in two different places to account for this -- nothing enforces it
/// stays that way if either format ever changes without the other side
/// noticing. See aci_executor.rs's own `maa_endpoint` field doc comment
/// for the other half of this.
#[cfg(feature = "aci-attestation")]
fn maa_endpoint() -> String {
    env_or("AZURE_ACI_MAA_ENDPOINT", "")
}

fn worker_timeout() -> Duration {
    Duration::from_secs_f64(env_or("AZURE_ACI_WORKER_TIMEOUT_SECS", "300").parse().unwrap_or(300.0))
}

// attester_service::attestation::mock_attestation_enabled() -- this
// binary's own path to the same shared lib code aci_executor.rs reaches
// via `crate::attestation` (see that file's own comment, and lib.rs's:
// this is exactly what the lib target exists for, so this binary never
// needed its own copy of that one boolean check).

/// The fixed placeholder aci_handshake() sends as its own
/// "attestation_document" when
/// attester_service::attestation::mock_attestation_enabled() is set --
/// not a real token, not parseable as one; aci_executor.rs's own verify_maa_token()
/// recognizes this exact string and skips real JWT verification only
/// when its own ATTESTER_MOCK_ATTESTATION is also set, never on the
/// strength of this string alone (a client sending this same bytes could
/// never reach that function directly -- attested_session.rs's own ACI
/// branch is what calls verify_maa_token(), never the client).
#[cfg(feature = "aci-attestation")]
const MOCK_MAA_TOKEN: &str = "mock-maa-token-no-real-attestation";

/// How long, in seconds, run_callback_session() sleeps just before
/// closing its own send side of the h2c stream (the signal
/// attested_session.rs waits on before tearing the container group
/// down -- see that file's own run_aci_job() comment). Debugging aid
/// only: gives an operator a real window to `az container exec`/inspect
/// a still-running container before ACI deletes it, instead of it
/// vanishing within moments of the primary response (and any queued
/// background work) finishing. 0 (the default) preserves today's
/// behavior exactly -- close immediately, no added latency for ordinary
/// sessions.
fn stayup_after() -> Duration {
    Duration::from_secs_f64(env_or("STAYUP_AFTER", "0").parse::<f64>().unwrap_or(0.0).max(0.0))
}

/// This container's own comma-separated operating options -- set once at
/// launch (aci_executor.rs's own create_group_body() propagates it the
/// same way ATTESTER_MOCK_ATTESTATION/STAYUP_AFTER already are), read
/// fresh each time rather than cached, the same discipline every other
/// env-backed setting in this file already follows. Not the same thing
/// as a client's own per-request `options` (client_hello's field) --
/// this is what the *worker* itself was launched to serve, checked by
/// is_shared_worker() below. Reported nowhere over the wire: attested_session.rs
/// already decided this when it launched the container (see that file's
/// own SharedWorkerPool), so there's nothing for this process to report
/// back.
#[cfg(feature = "aci-attestation")]
fn worker_execution_options() -> String {
    env_or("WORKER_EXECUTION_OPTIONS", "")
}

/// Whether this container should, after finishing a job, dial back into
/// the shared queue for another one instead of exiting -- see
/// aci_callback_handler()'s own loop for the mechanism, and
/// attested_session.rs's own SharedWorkerPool for the other half (what
/// bridges a *new* client onto this container instead of paying for a
/// fresh launch). Exact-token match against comma-separated
/// worker_execution_options(), not a substring search -- "not-shared" or
/// "shared-vpc" must not accidentally count.
#[cfg(feature = "aci-attestation")]
fn is_shared_worker() -> bool {
    worker_execution_options()
        .split(',')
        .any(|token| token.trim() == "shared")
}

/// How long a shared-mode container (is_shared_worker() above) sits in
/// attested_session.rs's own queue waiting for a matching client before
/// giving up and exiting for good. Irrelevant, never read, for a
/// non-shared container -- those always close after their one job, same
/// as before this existed. 30s default: long enough to catch a client
/// that arrives just after this container finished its previous job,
/// short enough that a container nobody ever reuses doesn't sit billing
/// idle for long. attested_session.rs reads the identically-named
/// WORKER_SHARED_IDLE_TIMEOUT_SECS from its own environment for the
/// matching half of this -- the queue entry's own expiry -- rather than
/// this process reporting its value back; both default to the same 30s
/// when neither side's env overrides it, so they agree without a wire
/// round trip.
#[cfg(feature = "aci-attestation")]
fn shared_worker_idle_timeout() -> Duration {
    Duration::from_secs_f64(
        env_or("WORKER_SHARED_IDLE_TIMEOUT_SECS", "30").parse::<f64>().unwrap_or(30.0).max(0.0),
    )
}

/// Caps how much of a queued job's own stdout/result/error a single log
/// line carries -- a real Hermes review transcript can be large, and
/// logs are for diagnosing what happened, not for reproducing the whole
/// output byte-for-byte. Truncates on a char boundary (not a byte index)
/// so this never panics on multi-byte UTF-8 content mid-character.
const LOG_TRUNCATE_CHARS: usize = 4000;

fn truncate_for_log(s: &str) -> String {
    if s.chars().count() <= LOG_TRUNCATE_CHARS {
        return s.to_string();
    }
    let truncated: String = s.chars().take(LOG_TRUNCATE_CHARS).collect();
    format!("{truncated}... (truncated, {} bytes total)", s.len())
}

/// Upper bound a queued background job's own `timeout_secs` field can ask
/// for -- a real reviewer run (run_reviewer() in worker.py) needs
/// materially longer than the primary request's own worker_timeout()
/// default (300s), but an unbounded per-job override would let one
/// malicious/broken queued job pin this container (and its billed ACI
/// uptime) open indefinitely, on top of attested_session.rs's own
/// aci_session_max_lifetime() bound.
fn max_queued_job_timeout() -> Duration {
    Duration::from_secs_f64(
        env_or("AZURE_ACI_MAX_QUEUED_JOB_TIMEOUT_SECS", "1800").parse().unwrap_or(1800.0),
    )
}

/// A queued job may ask for more time than the primary job gets (e.g. a
/// reviewer run) via its own `timeout_secs` field -- clamped to
/// max_queued_job_timeout(), and falling back to worker_timeout() (the
/// same bound the primary job always uses) when absent or malformed.
fn job_timeout(job: &serde_json::Value) -> Duration {
    match job.get("timeout_secs").and_then(|v| v.as_f64()) {
        Some(secs) if secs > 0.0 => {
            Duration::from_secs_f64(secs).min(max_queued_job_timeout())
        }
        _ => worker_timeout(),
    }
}

/// The unprivileged system user's numeric uid/gid -- set as fixed,
/// explicit values by the Dockerfile's own `useradd`, not looked up by
/// name at runtime, so this binary needs no extra dependency just to
/// resolve a username to an id.
fn worker_uid() -> u32 {
    env_or("WORKER_UID", "10001").parse().unwrap_or(10001)
}

fn worker_gid() -> u32 {
    env_or("WORKER_GID", "10001").parse().unwrap_or(10001)
}

// -- embedded SKR logic ---------------------------------------------------
//
// Gated behind the `aci-attestation` feature (see Cargo.toml's own
// comment) -- a build without it links none of this or the `sev` crate
// it pulls in.
//
// No sidecar container -- this process does what
// microsoft/confidential-sidecar-containers' own SKR sidecar does
// (pkg/attest/attest.go, pkg/common/maa.go, pkg/attest/platform_cert_fetcher.go,
// pkg/attest/snp_attestation_report.go -- read against their real Go
// source, not guessed), in-process, in Rust:
//
//   1. fetch the raw AMD SEV-SNP attestation report from /dev/sev-guest
//      via the `sev` crate, bound to report_data = SHA-256(runtime_data)
//      zero-padded to 64 bytes (GenerateMAAReportData())
//   2. read the platform's VCEK certificate + AMD cert chain, and the
//      UVM's own reference-info endorsement, off the local filesystem --
//      NOT a network call. Confidential ACI's control plane places these
//      under a `security-context-*` directory at container-group root
//      (or, on the now-deprecated env-var scheme, UVM_HOST_AMD_CERTIFICATE
//      / UVM_REFERENCE_INFO) at container-group launch -- see
//      pkg/common/info.go's own GetUvmInformationFromFiles()/
//      GetUvmInformationFromEnv(). This resolves what an earlier revision
//      of this comment left genuinely uncertain (whether THIM/UVM
//      endorsement lookup needs network reachability at all): it doesn't,
//      in the common case -- the report's own ReportedTCB is compared
//      against the locally-provided cert bundle's Tcbm, and only a
//      mismatch would need a live refresh.
//   3. assemble the same JSON shapes pkg/common/maa.go's
//      newAttestSNPRequestBody()/MAA.Attest() build, and POST directly to
//      MAA -- no sidecar in the loop at any point.
//
// DRAFT, UNTESTED against real hardware -- no real Confidential ACI
// deployment exists yet to confirm /dev/sev-guest and the
// security-context-* directory are actually present and populated inside
// an ordinary application container (as opposed to only the sidecar's own
// container, or only the UVM itself). That is exactly what real testing
// against a real deployment needs to confirm; this is built to that
// contract on paper, from the sidecar's own real source, not from
// assumption.
//
// KNOWN GAP: no live VCEK/cert-chain refresh path (AMD KDS or Azure's
// AzCache) if the locally-provided cert bundle's TCB doesn't match the
// freshly-fetched report's ReportedTCB -- get_maa_token() fails closed
// with a clear error in that case instead. The sidecar's own
// RefreshCertChain() exists for exactly this (a host microcode/firmware
// update between when the UVM was provisioned and when this report was
// pulled) -- worth adding once real testing shows it's actually needed,
// not built speculatively here.

#[cfg(feature = "aci-attestation")]
pub mod aci_attestation {
    use super::*;

    const SEV_GUEST_DEVICE_REPORT_SIZE: usize = 1184;
    const SEV_GUEST_REPORTED_TCB_OFFSET: usize = 384;

    const MAA_TEE_TYPE: &str = "SevSnpVM";
    const MAA_API_VERSION: &str = "api-version=2020-10-01";

/// Env var GCS/hcsshim sets on Confidential ACI when the UVM information
/// directory isn't just the one `/`-scanned entry matching
/// `security-context-*` (pkg/common/info.go's own
/// `GetUvmSecurityCtxDir()`). Falls back to scanning `/`, then to
/// Confidential AKS's own fixed default path.
const UVM_SECURITY_CONTEXT_DIR_ENV: &str = "UVM_SECURITY_CONTEXT_DIR";
const UVM_SECURITY_CONTEXT_DIR_DEFAULT: &str = "/opt/confidential-containers/share/kata-containers";
const HOST_AMD_CERT_FILENAME: &str = "host-amd-cert-base64";
const REFERENCE_INFO_FILENAME: &str = "reference-info-base64";

#[derive(Deserialize)]
struct ThimCerts {
    #[serde(rename = "vcekCert")]
    vcek_cert: String,
    tcbm: String,
    #[serde(rename = "certificateChain")]
    certificate_chain: String,
}

#[derive(Default)]
struct UvmInformation {
    initial_certs: Option<ThimCerts>,
    encoded_uvm_reference_info: Option<String>,
}

/// Matches a real reference implementation's own
/// `_find_security_context_dir()` (Azure-Samples/confidential-computing's
/// visual-attestation-demo-v2/app.py) exactly, including the part this
/// function was missing before: `UVM_SECURITY_CONTEXT_DIR` being set and
/// non-empty is not enough to trust it -- the directory has to actually
/// exist, or a stale/misconfigured env var silently short-circuits the
/// `/`-scan fallback below (and read_uvm_information()'s own caller falls
/// straight to the deprecated env-var scheme instead of ever finding a
/// real, populated `/security-context-*` directory sitting right there).
/// Same fix applies to the scan loop itself: check `is_dir()`, not just
/// the name prefix -- a same-named regular file at `/` would otherwise be
/// treated as a valid directory path too.
fn uvm_security_context_dir() -> Option<String> {
    if let Ok(dir) = std::env::var(UVM_SECURITY_CONTEXT_DIR_ENV) {
        if !dir.is_empty() {
            if std::path::Path::new(&dir).is_dir() {
                return Some(dir);
            }
            log::warn!(
                "uvm_security_context_dir: {UVM_SECURITY_CONTEXT_DIR_ENV}={dir:?} is set but is not a \
                 directory -- falling back to scanning / for security-context-* instead of trusting it"
            );
        }
    }
    if let Ok(entries) = std::fs::read_dir("/") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("security-context-") {
                    let path = format!("/{name}");
                    if std::path::Path::new(&path).is_dir() {
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

/// Mirrors pkg/common/info.go's own GetUvmInformation(): try the
/// files-based scheme first (current, Public-Preview-and-later), fall
/// back to the deprecated env-var scheme only if that produced nothing
/// usable.
fn read_uvm_information() -> UvmInformation {
    if let Some(dir) = uvm_security_context_dir() {
        let reference_info = std::fs::read_to_string(format!("{dir}/{REFERENCE_INFO_FILENAME}")).ok();
        let host_amd_cert = std::fs::read_to_string(format!("{dir}/{HOST_AMD_CERT_FILENAME}")).ok();
        if reference_info.is_some() || host_amd_cert.is_some() {
            return UvmInformation {
                initial_certs: host_amd_cert.and_then(|encoded| parse_thim_certs(&encoded)),
                encoded_uvm_reference_info: reference_info,
            };
        }
    } else {
        // Confidential AKS's own fixed default -- not scanned for, always
        // this exact path (pkg/common/info.go's own uvmSecurityCtxDirDefault).
        let dir = UVM_SECURITY_CONTEXT_DIR_DEFAULT;
        let reference_info = std::fs::read_to_string(format!("{dir}/{REFERENCE_INFO_FILENAME}")).ok();
        let host_amd_cert = std::fs::read_to_string(format!("{dir}/{HOST_AMD_CERT_FILENAME}")).ok();
        if reference_info.is_some() || host_amd_cert.is_some() {
            return UvmInformation {
                initial_certs: host_amd_cert.and_then(|encoded| parse_thim_certs(&encoded)),
                encoded_uvm_reference_info: reference_info,
            };
        }
    }

    UvmInformation {
        initial_certs: std::env::var("UVM_HOST_AMD_CERTIFICATE").ok().and_then(|encoded| parse_thim_certs(&encoded)),
        encoded_uvm_reference_info: std::env::var("UVM_REFERENCE_INFO").ok(),
    }
}

/// The `security-context-*`/env-var value is base64-STANDARD-encoded JSON
/// (pkg/common/info.go's own ParseTHIMCertsFromString()), not the
/// base64URL this module otherwise deals in -- MAA's own request encoding
/// starts only once we re-encode these fields for the request body below.
fn parse_thim_certs(base64_encoded_json: &str) -> Option<ThimCerts> {
    let decoded = general_purpose::STANDARD.decode(base64_encoded_json.trim()).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn reported_tcb(raw_report: &[u8]) -> Result<u64, SessionError> {
    if raw_report.len() != SEV_GUEST_DEVICE_REPORT_SIZE {
        return Err(SessionError::Protocol(format!(
            "SNP report from /dev/sev-guest was {} bytes, expected exactly {SEV_GUEST_DEVICE_REPORT_SIZE} \
             (the fixed AMD SEV-SNP ATTESTATION_REPORT size) -- the `sev` crate may be returning something \
             other than the bare report body",
            raw_report.len()
        )));
    }
    let offset = SEV_GUEST_REPORTED_TCB_OFFSET;
    let bytes: [u8; 8] = raw_report[offset..offset + 8]
        .try_into()
        .map_err(|_| SessionError::Protocol("could not slice ReportedTCB out of the SNP report".to_string()))?;
    Ok(u64::from_le_bytes(bytes))
}

fn tcbm_as_u64(tcbm_hex: &str) -> Result<u64, SessionError> {
    u64::from_str_radix(tcbm_hex.trim(), 16)
        .map_err(|e| SessionError::Protocol(format!("could not parse THIM certs' tcbm {tcbm_hex:?} as hex: {e}")))
}

#[derive(serde::Serialize)]
struct MaaReport {
    #[serde(rename = "SnpReport")]
    snp_report: String,
    #[serde(rename = "VcekCertChain")]
    vcek_cert_chain: String,
    #[serde(rename = "Endorsements", skip_serializing_if = "Option::is_none")]
    endorsements: Option<String>,
}

#[derive(serde::Serialize)]
struct MaaEndorsements {
    #[serde(rename = "Uvm")]
    uvm: Vec<String>,
}

#[derive(serde::Serialize)]
struct AttestedData {
    data: String,
    #[serde(rename = "dataType")]
    data_type: &'static str,
}

#[derive(serde::Serialize)]
struct AttestSnpRequestBody {
    report: String,
    #[serde(rename = "runtimeData")]
    runtime_data: AttestedData,
    nonce: u64,
}

#[derive(Deserialize)]
struct MaaTokenResponse {
    #[serde(alias = "Token")]
    token: Option<String>,
}

/// Fetch, assemble, and submit everything the SKR sidecar's own
/// `/attest/maa` handler would (see this module's own header comment for
/// the full breakdown) -- but in-process, using `runtime_data =
/// client_public_key_hash` directly rather than a sidecar round-trip.
///
/// Binding scheme, arrived at the hard way against a real MAA endpoint,
/// not guessed:
///
///   1. First attempt (dataType "JSON", raw client_public_key_hash
///      bytes): rejected -- "TeeDataType (x-ms-runtime) specified is
///      JSON but TeeData supplied is not parsable JSON". Raw hash bytes
///      are never valid JSON text.
///   2. Second attempt (dataType "Binary", same raw bytes): ALSO
///      rejected, differently -- "SevSnp only supports JSON RunTimeData
///      payload". Confirmed via two independent real Microsoft sources
///      (the ACI-specific confidential-containers-attestation-concepts
///      doc, and the general attest-sev-snp-vm REST schema) that
///      SevSnpVm's RuntimeData hard-requires `dataType: "JSON"` -- no
///      TEE-type exception the way SGX's own Binary usage might suggest.
///   3. This: dataType "JSON", with `runtime_data.data` a genuine JSON
///      object (`{"client_public_key_hash": <base64url>, "options_hash":
///      <base64url>}`), and `report_data` derived from *that JSON's own
///      bytes*, not either field directly -- MAA's own binding check
///      (`SHA256(runtime_data bytes) == REPORT_DATA`, confirmed
///      unconditional regardless of dataType) makes this the only
///      consistent choice once JSON is mandatory: report_data can't
///      simultaneously equal SHA-256(client_public_key_hash) directly
///      *and* SHA-256(any valid JSON text), since raw binary hash bytes
///      are never themselves valid JSON.
///
/// Both agent.py's own `verify_azure_aci_maa_attestation()` (backend
/// repo) and aci_executor.rs's own `verify_maa_claims()` in this repo
/// check `x-ms-runtime`'s parsed JSON content structurally (this exact
/// shape, both fields), not `x-ms-sevsnpvm-reportdata` directly --
/// confirmed matching on both sides, not assumed.
pub async fn get_maa_token(
    client: &reqwest::Client,
    client_public_key_hash: &[u8; 32],
    options: &str,
) -> Result<String, SessionError> {
    let endpoint = maa_endpoint();
    if endpoint.is_empty() {
        return Err(SessionError::Protocol("AZURE_ACI_MAA_ENDPOINT is not set".to_string()));
    }

    // `options` binds the same way client_public_key_hash does -- one
    // more field in the same runtime_data JSON, covered by the identical
    // report_data = SHA256(runtime_data bytes) hash MAA already enforces
    // unconditionally. Hashed rather than carried verbatim so this claim
    // stays a fixed-size commitment regardless of what a caller puts in
    // options (routing/billing tags today, whatever grows later) --
    // agent.py verifies it by hashing the plaintext `options` this
    // process echoes back in its own container_hello/server_hello, the
    // same shape client_public_key_hash's own binding already has
    // (hash inside the attested claim, real value carried in the open).
    // Always present, never conditional on options being non-empty --
    // "no options" is itself a value (the empty string), hashed the same
    // as any other, so there is exactly one binding shape to verify, not
    // two.
    let options_hash = sha2::Sha256::digest(options.as_bytes());
    let runtime_data_value = serde_json::json!({
        "client_public_key_hash": general_purpose::URL_SAFE_NO_PAD.encode(client_public_key_hash),
        "options_hash": general_purpose::URL_SAFE_NO_PAD.encode(options_hash),
    });
    let runtime_data_bytes = serde_json::to_vec(&runtime_data_value)?;

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&sha2::Sha256::digest(&runtime_data_bytes));

    // vmpl: Some(0), not None -- confirmed live, this is the actual fix
    // for the empty x-ms-compliance-status claim, not the
    // reference-info-base64/Endorsements path the log::warn! below was
    // originally suspected to point at (that path was independently
    // checked and was already correct). The `sev` crate's own
    // ReportReq::Default silently turns a `None` vmpl into vmpl: 1, not
    // "let the hardware pick" -- confirmed from its actual source.
    // Microsoft's own reference tool
    // (tools/get-snp-report/get-snp-report6.c,
    // microsoft/confidential-sidecar-containers) zero-initializes its
    // entire snp_report_req struct, VMPL field included, and never sets
    // it explicitly -- a zeroed struct already means VMPL 0, confirming
    // 0 (not 1, and not "whatever this process's own ambient VMPL is")
    // is the value MAA actually expects here. Verified two ways against
    // a real deployment: (1) this exact change produces a real, decoded
    // MAA token with `x-ms-sevsnpvm-vmpl: 0` and
    // `x-ms-compliance-status: azure-compliant-uvm` both present and
    // correct; (2) deploying Microsoft's own compiled
    // mcr.microsoft.com/aci/skr:2.12 sidecar as a plain, unprivileged
    // ACI Confidential container in the same subscription/region/MAA
    // endpoint independently gets the same vmpl: 0 /
    // azure-compliant-uvm result out of the box -- this is achievable
    // from an ordinary ACI container process, not something requiring
    // elevated privilege or a different platform.
    let raw_report = tokio::task::spawn_blocking(move || {
        let mut firmware = sev::firmware::guest::Firmware::open()
            .map_err(|e| SessionError::Protocol(format!("could not open /dev/sev-guest: {e}")))?;
        firmware
            .get_report(None, Some(report_data), Some(0))
            .map_err(|e| SessionError::Protocol(format!("SNP report request failed: {e}")))
    })
    .await
    .map_err(|e| SessionError::Protocol(format!("SNP report fetch task panicked: {e}")))??;

    let report_tcb = reported_tcb(&raw_report)?;

    let uvm_info = read_uvm_information();
    let initial_certs = uvm_info.initial_certs.ok_or_else(|| {
        SessionError::Protocol(
            "no local platform certificates found (no security-context-*/host-amd-cert-base64 and no \
             UVM_HOST_AMD_CERTIFICATE) -- cannot endorse the SNP report without a live cert-chain refresh, \
             which this binary does not yet implement"
                .to_string(),
        )
    })?;
    let cert_tcbm = tcbm_as_u64(&initial_certs.tcbm)?;
    if report_tcb != cert_tcbm {
        return Err(SessionError::Protocol(format!(
            "SNP report's ReportedTCB ({report_tcb}) does not match the locally-provided platform \
             certificates' Tcbm ({cert_tcbm}) -- likely a host firmware update since this UVM was \
             provisioned; refreshing the cert chain live (AMD KDS/AzCache) is not yet implemented"
        )));
    }
    let vcek_cert_chain = format!("{}{}", initial_certs.vcek_cert, initial_certs.certificate_chain);

    // Silently omitting this (rather than failing outright) matches
    // pkg/common/maa.go's own tolerance for a missing/undecodable
    // reference-info-base64. Checked and confirmed correct in this
    // codebase already (this file, this dir, decodes fine in a real
    // deployment) -- the empty x-ms-compliance-status claim this warning
    // was originally chasing turned out to be caused by the SNP report's
    // own requested VMPL instead (see get_report()'s own call site
    // above), not a missing endorsement. Kept as a real, live diagnostic
    // rather than removed: a genuinely missing/undecodable
    // reference-info-base64 would still be a real problem worth knowing
    // about (MAA can't check the UVM's own launch measurement against it
    // without this), just not the one this specific claim's emptiness
    // traced back to.
    let had_reference_info = uvm_info.encoded_uvm_reference_info.is_some();
    let endorsements = uvm_info
        .encoded_uvm_reference_info
        .filter(|s| !s.is_empty())
        .and_then(|encoded| general_purpose::STANDARD.decode(encoded.trim()).ok())
        .map(|uvm_reference_info_bytes| {
            let endorsements = MaaEndorsements { uvm: vec![general_purpose::URL_SAFE.encode(&uvm_reference_info_bytes)] };
            let json = serde_json::to_vec(&endorsements).expect("MaaEndorsements always serializes");
            general_purpose::URL_SAFE.encode(json)
        });
    if endorsements.is_none() {
        log::warn!(
            "get_maa_token: no usable UVM reference-info endorsement to submit to MAA \
             (reference-info-base64 file {}) -- MAA will still issue a token, but \
             x-ms-compliance-status will likely come back empty rather than \
             \"azure-compliant-uvm\" without it",
            if had_reference_info { "was found but failed to base64-decode" } else { "was not found under security-context-*/UVM_REFERENCE_INFO" }
        );
    }

    let maa_report = MaaReport {
        snp_report: general_purpose::URL_SAFE.encode(&raw_report),
        vcek_cert_chain: general_purpose::URL_SAFE.encode(vcek_cert_chain.as_bytes()),
        endorsements,
    };
    let maa_report_json = serde_json::to_vec(&maa_report)?;

    let request = AttestSnpRequestBody {
        report: general_purpose::URL_SAFE.encode(&maa_report_json),
        // The exact same JSON bytes report_data above was derived from --
        // see this function's own doc comment for why dataType must be
        // "JSON" (confirmed live, twice, that "Binary" is rejected
        // outright for SevSnpVm) and why that forces report_data away
        // from a direct hash of client_public_key_hash.
        runtime_data: AttestedData {
            data: general_purpose::URL_SAFE.encode(&runtime_data_bytes),
            data_type: "JSON",
        },
        nonce: rand::random(),
    };

    let uri = format!("https://{endpoint}/attest/{MAA_TEE_TYPE}?{MAA_API_VERSION}");
    let response = client
        .post(&uri)
        .json(&request)
        .send()
        .await
        .map_err(|e| SessionError::Protocol(format!("MAA request to {uri} failed: {e}")))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(SessionError::Protocol(format!("MAA {uri} returned {status}: {body}")));
    }
    let parsed: MaaTokenResponse = serde_json::from_str(&body)
        .map_err(|e| SessionError::Protocol(format!("MAA response was not the expected JSON shape: {e} (body: {body})")))?;
    parsed.token.ok_or_else(|| SessionError::Protocol(format!("MAA response had no token field (body: {body})")))
    }
} // mod aci_attestation

// -- worker execution, via bubblewrap ----------------------------------------
//
// This image carries no Python and no baked-in worker.py/storage.py at
// all -- every session fetches its own self-contained runtime tarball
// (worker-python-runtime, a separate, public repo) fresh, by content
// hash. `storage_grant` is still read from the request -- that's what
// storage.py itself uses at runtime to reach World's own KV/S3 storage,
// a separate concern from how worker.py's own source arrived.
//
// Sandlock (Landlock LSM + seccomp-bpf) replaced with bubblewrap
// (unprivileged user/mount/pid namespaces) this session: confirmed live
// that Azure ACI's own node kernel (6.1.146-microsoft-standard) and
// Docker Desktop's linuxkit VM kernel (6.12.54) both lack
// CONFIG_SECURITY_LANDLOCK entirely (see the removed sandlock_self_test()'s
// own doc comment, in this file's own git history, for the full story) --
// a kernel-build gap sandlock had no way around. User namespaces are the
// one confinement primitive confirmed available on those same hosts, and
// bubblewrap is the standard, widely-deployed tool built on exactly that
// primitive (used by Flatpak sandboxing, among others) -- a real,
// maintained project, not something hand-rolled the way sandlock's own
// fork was.
const BWRAP_BIN: &str = "bwrap";

/// Fetches, verifies, and extracts a worker runtime bundle -- a tar.gz
/// containing a self-contained Python interpreter, its own dependencies,
/// and worker.py/storage.py themselves (worker-python-runtime, a
/// separate, public repo; see that repo's own README) -- from the
/// shared/global CAS prefix (`v4/assets/<hash>` by default, matching
/// storage.py's own `Bucket.asset_prefix`), reusing the SAME
/// storage_grant credential the request already carries for worker.py's
/// own S3 access: no new credential-minting capability, no new trust
/// boundary crossed. The bundle is content-addressed and never
/// encrypted, same posture as world.py's own bootstrap body and the
/// reviewer bundle -- this is infrastructure, not account-private data.
///
/// Extracted to a fixed, hash-named directory under /tmp
/// (worker-runtime-<hash>/) rather than a single file: unlike the
/// earlier zip-of-two-files shape (zipimport, PYTHONPATH-mounted,
/// nothing ever unpacked), this bundle carries a real interpreter binary
/// that has to exist on disk as an actual file bwrap can bind and exec,
/// not something Python's own import machinery can resolve out of an
/// archive in-memory. Idempotent by construction: if
/// <dir>/runtime/runtime already exists, this is a cache hit and nothing
/// is fetched or re-extracted -- the common case for a shared-worker-pool
/// container serving more than one job across its own lifetime (see
/// is_shared_worker()'s own doc comment), which would otherwise pay this
/// fetch/extract cost on every job instead of once.
///
/// Fails closed: a malformed grant, an unreachable store, a non-200
/// response, a body whose own SHA-256 doesn't match the requested hash,
/// or a tar.gz that fails to extract all return `Err` -- run_worker()
/// refuses the whole request rather than running anything it couldn't
/// fully verify, since a caller that named a specific hash and didn't
/// get it back should never run a different body than the one it asked
/// for. There is no baked-in fallback to silently run instead.
///
/// Who supplies `sha256_hex` matters more than anything in this function:
/// it must be a reviewed, pinned constant the attested client itself
/// carries (agent.py's own committed value, trusted_hashes.py's
/// ACI_WORKER_BUNDLE_SHA256), never derived, fetched, or accepted from an
/// unreviewed source at runtime -- the same posture trusted_hashes.py's
/// own module doc already argues for. This function only ever verifies
/// that the bytes match the hash it was given; it has no opinion on
/// whether that hash was the right one to ask for.
///
/// Not feature-gated, matching run_worker() itself (its caller) -- see the
/// s3::/sha2:: import comments above.
async fn fetch_worker_bundle(
    storage_grant: &serde_json::Value,
    sha256_hex: &str,
) -> Result<std::path::PathBuf, String> {
    if sha256_hex.len() != 64 || !sha256_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid worker_bundle sha256: {sha256_hex:?}"));
    }
    let sha256_hex = sha256_hex.to_ascii_lowercase();

    let extract_dir = std::path::PathBuf::from(format!("/tmp/worker-runtime-{sha256_hex}"));
    let runtime_entry_point = extract_dir.join("runtime").join("runtime");
    if tokio::fs::metadata(&runtime_entry_point).await.is_ok() {
        return Ok(extract_dir.join("runtime"));
    }

    let get_str = |field: &str| -> Result<String, String> {
        storage_grant
            .get(field)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("storage_grant missing {field}"))
    };
    let access_key_id = get_str("access_key_id")?;
    let secret_access_key = get_str("secret_access_key")?;
    let bucket_name = get_str("bucket")?;
    let endpoint = get_str("endpoint")?;
    let region = storage_grant
        .get("region")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("auto")
        .to_string();
    // Same default storage.py's own Bucket.asset_prefix property falls
    // back to when the grant doesn't carry one explicitly.
    let asset_prefix = storage_grant
        .get("asset_prefix")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("v4/assets/");

    let credentials = Credentials::new(Some(&access_key_id), Some(&secret_access_key), None, None, None)
        .map_err(|e| format!("worker_bundle credentials: {e}"))?;
    let bucket = Bucket::new(&bucket_name, Region::Custom { region, endpoint }, credentials)
        .map_err(|e| format!("worker_bundle bucket: {e}"))?
        .with_path_style();

    let key = format!("{asset_prefix}{sha256_hex}");
    let response = bucket
        .get_object(&key)
        .await
        .map_err(|e| format!("worker_bundle fetch {key}: {e}"))?;
    if response.status_code() != 200 {
        return Err(format!("worker_bundle fetch {key}: HTTP {}", response.status_code()));
    }
    let body = response.to_vec();

    let digest = hex::encode(sha2::Sha256::digest(&body));
    if digest != sha256_hex {
        return Err(format!(
            "worker_bundle {key} did not match its own content-addressed hash (got {digest})"
        ));
    }

    // Extract into a fresh temp dir first, then rename into place --
    // extraction failing partway through must never leave a directory at
    // extract_dir that looks cache-hit-eligible (runtime/runtime present)
    // but is actually incomplete/corrupt.
    let tmp_dir = std::path::PathBuf::from(format!("/tmp/worker-runtime-{sha256_hex}.tmp"));
    let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
    tokio::fs::create_dir_all(&tmp_dir)
        .await
        .map_err(|e| format!("worker_bundle mkdir {tmp_dir:?}: {e}"))?;
    {
        let tmp_dir = tmp_dir.clone();
        tokio::task::spawn_blocking(move || {
            let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(body));
            tar::Archive::new(decoder).unpack(&tmp_dir)
        })
        .await
        .map_err(|e| format!("worker_bundle extract {key}: join error: {e}"))?
        .map_err(|e| format!("worker_bundle extract {key}: {e}"))?;
    }
    if tokio::fs::metadata(tmp_dir.join("runtime").join("runtime"))
        .await
        .is_err()
    {
        return Err(format!(
            "worker_bundle {key} extracted but runtime/runtime is missing -- not a valid worker-python-runtime tarball"
        ));
    }
    let _ = tokio::fs::remove_dir_all(&extract_dir).await;
    tokio::fs::rename(&tmp_dir, &extract_dir)
        .await
        .map_err(|e| format!("worker_bundle rename {tmp_dir:?} -> {extract_dir:?}: {e}"))?;

    Ok(extract_dir.join("runtime"))
}

#[derive(serde::Serialize)]
struct WorkerFailure<'a> {
    ok: bool,
    result: Option<()>,
    error: &'a str,
    stdout: &'a str,
}

/// A real, live check, not just "is the binary present": creating a user
/// namespace can still fail on a host that otherwise has bubblewrap
/// installed -- e.g. `kernel.unprivileged_userns_clone` disabled, or a
/// container runtime's own seccomp profile blocking the `clone`/`unshare`
/// calls involved (confirmed hitting exactly that failure mode locally
/// under this repo's own sandboxed dev shell, a different environment
/// from either real target this session cared about -- ACI's node and
/// Docker Desktop's linuxkit VM, where user namespaces are the confirmed-
/// available primitive that motivated this switch in the first place).
/// Cached via bwrap_available() -- see that function's own doc comment
/// for the sandboxless fallback this drives on a host that fails it.
///
/// `--ro-bind /bin /bin --ro-bind /lib /lib`: this only has to prove
/// bubblewrap can confine *something*, not run a real worker -- `true`
/// needs both paths for the same reason the fetched runtime's own
/// interpreter invocation needs `/usr`+`/lib` below (a
/// dynamically-linked musl binary needs its loader readable, not just
/// its own binary).
///
/// No `--proc /proc`: confirmed live on a real Confidential ACI container
/// that this specific flag is what fails there ("Can't mount proc on
/// /proc: Operation not permitted"), isolated precisely -- removing only
/// this flag from an otherwise-identical invocation succeeds (exit 0),
/// and the same failure reproduces with plain `unshare --user --pid
/// --mount-proc` and even an unnamespaced `mount -t proc` as the
/// container's own root. ACI containers block mounting a *new* procfs
/// at the container boundary itself (no CAP_SYS_ADMIN for that specific
/// operation, or a seccomp rule targeting it specifically) -- the same
/// well-known hardening most unprivileged Docker/OCI runtimes apply
/// (mounting a fresh procfs from inside a container has been a real
/// privilege-escalation vector historically), and a nested user
/// namespace's own root doesn't get back a capability the outer
/// boundary already denies. `--dev`/`--tmpfs` mounts are unaffected --
/// this is specifically about procfs, not mounting in general. Dropping
/// it recovers real bubblewrap confinement (user/mount/ipc/uts namespace
/// isolation) on ACI instead of the sandboxless fallback -- CPython
/// doesn't hard-require a mounted /proc for ordinary script execution
/// (os.cpu_count()/threading/ssl/tempfile all have non-/proc code
/// paths), though that specific claim hasn't been verified live against
/// worker.py itself in this session, only reasoned from documented
/// CPython/musl behavior -- worth confirming directly against a real
/// ACI container before trusting it fully.
async fn bwrap_self_test() -> bool {
    match Command::new("timeout")
        .arg("-s").arg("9")
        .arg("-k").arg("2")
        .arg("5")
        .arg(BWRAP_BIN)
        .arg("--unshare-all").arg("--share-net")
        .arg("--die-with-parent")
        .arg("--new-session")
        .arg("--dev").arg("/dev")
        .arg("--ro-bind").arg("/bin").arg("/bin")
        .arg("--ro-bind").arg("/lib").arg("/lib")
        .arg("--")
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) if status.success() => true,
        Ok(status) => {
            log::error!("bubblewrap self-test (`bwrap ... -- true`) exited {status}");
            false
        }
        Err(e) => {
            log::error!("bubblewrap self-test could not even spawn ({e})");
            false
        }
    }
}

static BWRAP_AVAILABLE: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

/// Cached result of bwrap_self_test() -- checked once (either at startup,
/// via main()'s own log line, or lazily on first use) rather than per-
/// request, since a host's own user-namespace support can't change
/// mid-process.
///
/// Sandboxless fallback here, same shape the earlier sandlock-based
/// version had: current goal on a host that fails this is reaching and
/// exercising the attestation path end to end, not insisting on
/// isolation everywhere -- run_worker() falls back to plain
/// `python3 <script>` (no bubblewrap wrapper at all) rather than
/// refusing to start.
async fn bwrap_available() -> bool {
    *BWRAP_AVAILABLE.get_or_init(bwrap_self_test).await
}

/// Runs the fetched worker_bundle runtime natively (its own bundled
/// interpreter, no emulation) inside a bubblewrap sandbox -- unprivileged
/// user/mount/pid namespaces, enforced by the kernel directly against the
/// real process, not a RISC-V guest the way the earlier rvlinux-based
/// sandbox worked. Feeds `request` on stdin and reads the response from
/// stdout, exactly the same request/response shape run_worker_subprocess()
/// (the original, unsandboxed `python3 <script>` predecessor of this
/// function) already used -- only the execution engine changed, not the
/// protocol.
///
/// Readable paths are the minimum this repo has confirmed the bundled
/// interpreter/TLS stack actually need: `/usr` and `/lib` (the musl
/// dynamic loader and system shared libraries the bundled interpreter's
/// own binary links against) for it to start at all, `/bin` for scripts
/// unpacked into `/tmp` whose shebangs and subprocesses use the system
/// shell, `/etc/ssl` and `/etc/resolv.conf`/`/etc/hosts` for storage.py's
/// own real HTTPS S3 calls, and the extracted worker_bundle directory
/// itself (fetch_worker_bundle()'s own doc comment) for the interpreter,
/// its dependencies, and worker.py/storage.py all together.
/// `--share-net` (kept, not unshared, as part of `--unshare-all`): full
/// outbound socket access, the same unrestricted network posture the
/// sandlock-based version's `--net-allow '*'` gave -- fine-grained
/// network ACLs are a well-scoped follow-up, not part of this swap.
/// `/tmp` is a fresh tmpfs and is explicitly mode 1777: worker code runs as
/// uid 10001, so the tmpfs mount's root-owned default mode would otherwise
/// prevent it from unpacking reviewer payloads there. `--dev` is freshly
/// synthesized inside the new namespaces (not bind-
/// mounted from the host) -- a minimal `/dev` (null, zero, full, random,
/// urandom, tty) is enough for CPython.
///
/// No `--proc /proc`, deliberately: confirmed live against a real
/// Confidential ACI container that mounting a *new* procfs is exactly
/// what fails there ("Can't mount proc on /proc: Operation not
/// permitted"), isolated precisely by removing only that one flag from
/// an otherwise-identical invocation and confirming it then succeeds --
/// reproduced the same failure with plain `unshare --user --pid
/// --mount-proc` and even an unnamespaced `mount -t proc` as the
/// container's own root, so this is ACI's own container boundary
/// blocking new procfs mounts specifically (well-known hardening most
/// unprivileged Docker/OCI runtimes apply, since a fresh procfs mount
/// from inside a container has been a real privilege-escalation vector
/// historically), not something a nested user namespace's own root can
/// route around. `--dev`/`--tmpfs` mounts are unaffected -- this is
/// specific to procfs. CPython doesn't hard-require a mounted `/proc`
/// for ordinary script execution (documented non-`/proc` code paths for
/// `os.cpu_count()`, threading, `ssl`, `tempfile`), but that claim
/// hasn't been verified live against worker.py itself in this session --
/// confirm directly against a real ACI container before trusting it
/// fully if anything downstream ever starts behaving oddly without one.
///
/// No memory limit here, unlike sandlock's own `-m` flag -- bubblewrap
/// has no built-in equivalent (it isn't a resource-limiting tool, only a
/// namespacing one); a real limit would mean this process itself
/// managing a cgroup, not yet built. Known gap, not an oversight -- the
/// current goal is reaching attestation, not full-parity isolation.
///
/// No `-t`-equivalent either: wrapped in the standalone `timeout`
/// utility instead (`-s 9` sends SIGKILL directly; `-k 5` is a follow-up
/// KILL 5s later as insurance in case the first somehow didn't land),
/// relying on `--die-with-parent` to propagate that into the sandboxed
/// process once `timeout` kills bwrap itself -- the same two-layer shape
/// sandlock's own `-t` plus this function's own `kill_on_drop` backstop
/// had, just built from a generic OS utility instead of a sandbox-
/// specific flag.
///
/// Still runs as the unprivileged `worker` uid/gid *inside* bubblewrap's
/// own new user namespace (`--uid`/`--gid`, which requires
/// `--unshare-user` -- already implied by `--unshare-all`) rather than on
/// the host process the way sandlock's version dropped privilege --
/// session_master itself runs as root (needed elsewhere, e.g. reading
/// `/dev/sev-guest`), so mapping down to an unprivileged id only inside
/// the sandbox's own namespace is the bubblewrap-idiomatic way to achieve
/// the same "worker code never runs as root" property.
///
/// Falls back to running worker.py unsandboxed on a host that fails
/// bwrap_available()'s own self-test -- see that function's own doc
/// comment for why.
///
/// A non-zero exit, a timeout, or a response that doesn't parse as JSON
/// all come back as an ordinary `{"ok": false, "error": ...}` value --
/// the caller always gets a JSON value back, never an exception to
/// handle separately.
///
/// bwrap_self_test()'s own shape (`--unshare-all --share-net
/// --die-with-parent --new-session --dev /dev`, minus `--proc /proc`) is
/// confirmed live to actually run on a real Confidential ACI container
/// -- see that function's own doc comment. This function's fuller
/// invocation (the extra `--ro-bind`s, `--tmpfs /tmp`, `--uid`/`--gid`,
/// and running python3 rather than `true`) hasn't been separately
/// confirmed yet, nor has either shape against Docker Desktop's own
/// linuxkit VM target, nor whether worker.py's real workloads behave
/// correctly with no `/proc` at all -- still DRAFT on those specific
/// points. (This repo's own sandboxed dev shell hit a different,
/// unrelated failure trying to reproduce any of this locally --
/// "Failed to make / slave: Permission denied" even with
/// `--security-opt seccomp=unconfined` -- a property of that particular
/// nested dev environment, not ACI's own narrower procfs-specific
/// restriction described above.) Built against bubblewrap's own real,
/// verified `--help` output, not guessed.
async fn run_worker(request: &serde_json::Value, timeout: Duration) -> serde_json::Value {
    let payload = match serde_json::to_vec(request) {
        Ok(p) => p,
        Err(e) => return worker_failure(&format!("could not serialize request: {e}")),
    };

    // Mandatory: this image carries no Python and no baked-in
    // worker.py/storage.py at all, so a request with no `worker_bundle`
    // field has nothing this binary could possibly run -- refused
    // outright, the same "unverifiable/absent code does not get
    // executed" posture install.sh's own setup-script check already
    // uses. See fetch_worker_bundle()'s own doc comment for the
    // fetch/verify/extract this resolves.
    let Some(sha256_hex) = request
        .get("worker_bundle")
        .and_then(|v| v.get("sha256"))
        .and_then(|v| v.as_str())
    else {
        return worker_failure(
            "request carries no worker_bundle -- this image has no baked-in default to fall back to",
        );
    };
    let Some(storage_grant) = request.get("storage_grant") else {
        return worker_failure("worker_bundle given but request carries no storage_grant");
    };
    let worker_bundle_path = match fetch_worker_bundle(storage_grant, sha256_hex).await {
        Ok(path) => path,
        Err(e) => return worker_failure(&format!("could not resolve worker_bundle: {e}")),
    };

    // kill_on_drop: without this, dropping `child` (which is exactly what
    // happens below when our own tokio::time::timeout fires and abandons
    // the wait_with_output() future) leaves the real OS process running
    // as an orphan -- confirmed live, via a real `subprocess.Popen` +
    // `.wait(timeout=...)` repro of this exact pattern, that giving up on
    // a wait alone never kills anything. A backstop behind the `timeout`-
    // wrapped bwrap invocation's own kill (propagated into the sandbox by
    // `--die-with-parent`), not the only enforcement -- but cheap
    // insurance against the two racing differently than expected.
    //
    // Two shapes below, chosen by bwrap_available() -- see that
    // function's own doc comment for why a sandboxless fallback exists
    // at all on hosts confirmed to lack a working user-namespace sandbox.
    //
    // worker_bundle_path is the extracted runtime directory
    // (fetch_worker_bundle()'s own doc comment) -- bound whole, and
    // exec'd via its own `runtime` entry-point script rather than a
    // `python3 -c` invocation: there is no base-image python3 to invoke
    // at all anymore, and the entry point itself already knows how to
    // launch worker.py correctly (see worker-python-runtime's own
    // README). No PYTHONPATH needed either -- worker.py/storage.py live
    // in this same tree's own site-packages, already on the bundled
    // interpreter's default sys.path.
    let bundle = worker_bundle_path.to_string_lossy().into_owned();
    let entry_point = worker_bundle_path.join("runtime").to_string_lossy().into_owned();
    let mut command = if bwrap_available().await {
        let mut c = Command::new("timeout");
        c.arg("-s").arg("9")
            .arg("-k").arg("5")
            .arg(timeout.as_secs().to_string())
            .arg(BWRAP_BIN)
            .arg("--unshare-all").arg("--share-net")
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--dev").arg("/dev")
            .arg("--ro-bind").arg("/bin").arg("/bin")
            .arg("--ro-bind").arg("/usr").arg("/usr")
            .arg("--ro-bind").arg("/lib").arg("/lib")
            .arg("--ro-bind").arg("/etc/ssl").arg("/etc/ssl")
            .arg("--ro-bind").arg("/etc/resolv.conf").arg("/etc/resolv.conf")
            .arg("--ro-bind").arg("/etc/hosts").arg("/etc/hosts")
            .arg("--tmpfs").arg("/tmp")
            .arg("--chmod").arg("1777").arg("/tmp")
            .arg("--setenv").arg("PYTHONDONTWRITEBYTECODE").arg("1")
            .arg("--uid").arg(worker_uid().to_string())
            .arg("--gid").arg(worker_gid().to_string())
            // The --ro-bind for the bundle dir must come after --tmpfs
            // /tmp above, not before -- bwrap applies mount actions in
            // argument order, and a bind targeting a path under /tmp
            // issued before the fresh tmpfs is mounted there would just
            // be shadowed by it.
            .arg("--ro-bind").arg(&bundle).arg(&bundle)
            .arg("--")
            .arg(&entry_point);
        c
    } else {
        let mut c = Command::new(&entry_point);
        c.env("PYTHONDONTWRITEBYTECODE", "1")
            .uid(worker_uid())
            .gid(worker_gid());
        c
    };
    let mut child = match command
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return worker_failure(&format!("could not spawn worker: {e}")),
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(&payload).await {
            return worker_failure(&format!("could not write request to worker stdin: {e}"));
        }
        drop(stdin);
    }

    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return worker_failure(&format!("worker subprocess error: {e}")),
        Err(_) => return worker_failure(&format!("worker timed out after {timeout:?}")),
    };

    if !output.status.success() {
        return worker_failure(&format!(
            "worker subprocess exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    match serde_json::from_slice::<serde_json::Value>(&output.stdout) {
        Ok(v) => v,
        Err(e) => worker_failure(&format!(
            "malformed worker response: {e} (stdout: {}, stderr: {})",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )),
    }
}

fn worker_failure(message: &str) -> serde_json::Value {
    serde_json::to_value(WorkerFailure { ok: false, result: None, error: message, stdout: "" })
        .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": message}))
}

// -- session handling ------------------------------------------------------
//
// run_callback_session() below is the actual per-job work, once a
// callback stream is open and a session_key exists -- see this file's
// own module doc comment for the full sequence aci_callback_handler()
// runs before it.

/// A queued background eval waiting to run once the primary request's
/// response has been sent -- see spawn_queue_listener()'s own doc
/// comment for how it gets here.
const MAX_QUEUED_EVALS: usize = 16;

/// Opens a loopback listener that worker.py's own sandboxed eval code
/// can dial back into (via worker.py's `queue_eval()`) to queue one more
/// `{mode, code, storage_grant, pattern_delegate}` job to run after the
/// primary request's response has already been sent -- the "tail call"
/// primitive: the caller gets its answer and its connection winds down
/// normally, but this container keeps running the queued job(s)
/// afterward, inside the same attested environment, before it finally
/// exits. Reachable from inside run_worker()'s bwrap sandbox because
/// that sandbox keeps `--share-net` (the sandbox shares this process's
/// own network namespace rather than a private one) -- not reachable
/// from outside this container at all, since it only ever binds
/// 127.0.0.1 on an OS-assigned port.
///
/// `token` gates it: a connection has to present the exact token minted
/// for this one request (carried into worker.py via the primary
/// request's own injected `queue_token` field) to have anything it sends
/// accepted -- otherwise nothing stops some other process reachable on
/// this loopback interface from queuing work into a session it wasn't
/// handed. Returns the bound address (also injected into the primary
/// request, as `queue_addr`) and the receiving half of the channel
/// queued jobs land in; run_callback_session() drains whatever is
/// already there once the primary job's own subprocess has exited --
/// see that function's own comment for why that's a drain, not a wait.
async fn spawn_queue_listener(
    token: String,
) -> std::io::Result<(std::net::SocketAddr, tokio::sync::mpsc::Receiver<serde_json::Value>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::mpsc::channel(MAX_QUEUED_EVALS);

    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    log::warn!("background-eval queue listener accept failed: {e}");
                    continue;
                }
            };
            tokio::spawn(handle_queue_connection(stream, token.clone(), tx.clone()));
        }
    });

    Ok((addr, rx))
}

/// One queue request/response, framed the same length-prefixed way
/// session_protocol::read_frame/write_frame already use for
/// attested_session.rs's own client-facing raw TCP protocol -- reused
/// verbatim since this is the same shape (plain length-prefixed JSON
/// over a TcpStream), just unencrypted: this socket never leaves the
/// container's own loopback interface, so there is no transport to
/// protect the way the client-facing protocol's AEAD layer protects a
/// real network hop. Always writes back a `{"ok": ...}` response before
/// closing -- worker.py's own queue_eval() waits for it, so a job is
/// never silently dropped without the caller finding out.
async fn handle_queue_connection(
    mut stream: tokio::net::TcpStream,
    token: String,
    tx: tokio::sync::mpsc::Sender<serde_json::Value>,
) {
    let outcome = handle_queue_connection_inner(&mut stream, &token, &tx).await;
    let response = match outcome {
        Ok(()) => serde_json::json!({"ok": true}),
        Err(e) => {
            log::warn!("background-eval queue request rejected: {e}");
            serde_json::json!({"ok": false, "error": e})
        }
    };
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let _ = write_frame(&mut stream, &bytes).await;
    }
}

async fn handle_queue_connection_inner(
    stream: &mut tokio::net::TcpStream,
    token: &str,
    tx: &tokio::sync::mpsc::Sender<serde_json::Value>,
) -> Result<(), String> {
    let frame = read_frame(stream).await.map_err(|e| e.to_string())?;
    let mut job: serde_json::Value = serde_json::from_slice(&frame).map_err(|e| e.to_string())?;
    let obj = job
        .as_object_mut()
        .ok_or_else(|| "queue request was not a JSON object".to_string())?;
    let presented = obj
        .remove("queue_token")
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| "missing queue_token".to_string())?;
    if presented != token {
        return Err("invalid queue_token".to_string());
    }
    tx.try_send(job).map_err(|_| "background-eval queue is full".to_string())
}

/// The actual per-session work, once a callback stream is open and a
/// session_key exists: read one client-to-server frame, decrypt,
/// run_worker(), encrypt, write one server-to-client frame, then run
/// whatever background eval(s) got queued (see spawn_queue_listener())
/// before finally closing the stream.
///
/// `stayup_on_close`: whether STAYUP_AFTER's own debug delay (see that
/// function's doc comment) applies to *this* stream's close. True only
/// when the caller knows this close is what tears the container down --
/// an ordinary non-shared job, always exactly one -- false for every
/// ordinary job a shared worker runs, since attested_session.rs never
/// tears a shared worker down just because one job's stream closed (it
/// expects a rejoin); sleeping there would only slow down every job in
/// the queue for no debugging benefit, since nothing is about to delete
/// the container. aci_callback_handler()'s own shared-queue loop applies
/// the delay itself, once, at the point it actually gives up (the queue
/// wait times out or the container drops out for good) rather than here.
async fn run_callback_session(
    session_key: [u8; 32],
    callback_addr: &str,
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    stayup_on_close: bool,
) -> Result<(), SessionError> {
    log::info!("run_callback_session: reading request frame");
    let request_frame = h2_read_frame(&mut recv).await?;
    log::info!("run_callback_session: got request frame, {} bytes, decrypting", request_frame.len());
    let request_plaintext = open(&session_key, &request_frame, &client_to_server_aad())?;
    let mut request: serde_json::Value = serde_json::from_slice(&request_plaintext)?;
    log::info!("run_callback_session: decrypted ok, running worker via bubblewrap");

    // Not fatal if this fails to bind: the primary request still runs
    // fine without background-queue support, worker.py's own
    // queue_eval() just reports it unavailable (no queue_token/
    // queue_addr present in the request it got).
    let mut queue_rx = None;
    let queue_token = uuid::Uuid::new_v4().to_string();
    match spawn_queue_listener(queue_token.clone()).await {
        Ok((addr, rx)) => {
            if let Some(obj) = request.as_object_mut() {
                obj.insert("queue_token".to_string(), serde_json::Value::String(queue_token));
                obj.insert("queue_addr".to_string(), serde_json::Value::String(addr.to_string()));
            }
            queue_rx = Some(rx);
        }
        Err(e) => log::warn!("run_callback_session: could not open background-eval queue listener: {e}"),
    }

    // Always overwritten, never trusted from the request even though
    // nothing sensitive rides on it (the same address the primary
    // session's own dial-out already used, just handed to worker.py too)
    // -- this is the address worker.py's own local.connect()-style
    // dial-out (once built) would present callback_id/aes_key at, to
    // reach whatever registered that callback_id via attested_session.rs's
    // own REGISTER_CALLBACK_PATH. Distinct from queue_addr (a loopback
    // address inside this container) -- this one leaves the container
    // entirely, back out to attester-service.
    if let Some(obj) = request.as_object_mut() {
        obj.insert("callback_addr".to_string(), serde_json::Value::String(callback_addr.to_string()));
    }

    let start = Instant::now();
    let mut response = run_worker(&request, worker_timeout()).await;
    log::info!("run_callback_session: got worker response, sealing and writing");
    if let Some(obj) = response.as_object_mut() {
        obj.insert("authorized".to_string(), serde_json::Value::Bool(true));
        obj.insert("bypassed".to_string(), serde_json::Value::Bool(false));
        obj.insert(
            "execution_duration_ms".to_string(),
            serde_json::Value::from(start.elapsed().as_millis() as u64),
        );
    }

    let sealed = seal(&session_key, serde_json::to_vec(&response)?.as_slice(), &server_to_client_aad());
    // end_stream=false, unlike this function's own pre-background-queue
    // shape: a queued eval (if any) still needs this same h2c stream to
    // stay open while it runs below. attested_session.rs no longer tears
    // the container down the moment it has this one frame -- it now
    // waits for the stream to actually close (see its own
    // run_aci_job() comment) -- so closing it here would be
    // premature.
    h2_write_frame(&mut send, &sealed, false)?;
    log::info!("run_callback_session: h2_write_frame returned Ok, {} bytes sealed+framed", sealed.len());

    // Drain whatever is already queued -- not a wait for more to arrive.
    // Queuing only ever happens synchronously from within the worker.py
    // subprocess run_worker() just waited on above, and that subprocess
    // has already exited by this point, so nothing new can land in this
    // channel from here on.
    if let Some(mut rx) = queue_rx {
        let mut ran = 0u32;
        while let Ok(job) = rx.try_recv() {
            ran += 1;
            log::info!("run_callback_session: running queued background eval {ran}");
            let result = run_worker(&job, job_timeout(&job)).await;
            let ok = result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            log::info!("run_callback_session: queued background eval {ran} finished, ok={ok}");
            // worker.py's own response shape: {"ok", "result", "stdout",
            // ["error"]} -- `result` is a queued eval's own auto-captured
            // trailing expression (e.g. world._run_reviewer_agent()'s
            // return dict, already repr()'d to a string by worker.py, not
            // this process), `stdout` is whatever the submitted code
            // print()ed. Previously silently dropped once `ok` was read --
            // confirmed live as a real gap: a queued reviewer run's own
            // stdout/stderr/result were only ever visible if something
            // failed outright, never on a clean `ok=true` exit, which
            // meant "it ran without raising" and "it actually did
            // something useful" were indistinguishable from this log
            // alone.
            if let Some(stdout) = result.get("stdout").and_then(|v| v.as_str()) {
                if !stdout.is_empty() {
                    log::info!(
                        "run_callback_session: queued background eval {ran} stdout: {}",
                        truncate_for_log(stdout)
                    );
                }
            }
            if let Some(value) = result.get("result") {
                if !value.is_null() {
                    // Almost always a plain string (run_eval()/run_repl()'s
                    // own repr() of the queued code's trailing expression)
                    // -- printed unquoted/unescaped when it is one, rather
                    // than through Value's own Display (which would add a
                    // second, JSON-escaped layer of quoting on top of
                    // worker.py's already-repr()'d text).
                    let text = value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string());
                    log::info!(
                        "run_callback_session: queued background eval {ran} result: {}",
                        truncate_for_log(&text)
                    );
                }
            }
            if let Some(error) = result.get("error").and_then(|v| v.as_str()) {
                log::warn!(
                    "run_callback_session: queued background eval {ran} error: {}",
                    truncate_for_log(error)
                );
            }
        }
        if ran > 0 {
            log::info!("run_callback_session: ran {ran} queued background eval(s)");
        }
    }

    // Only when the caller knows this stream's own close is what tears
    // the container down (an ordinary, non-shared job, or the last job a
    // shared worker will ever run) -- see `stayup_on_close`'s own doc
    // comment on this function, and aci_callback_handler()'s own callers
    // for why a shared worker's *ordinary* job closes skip this and the
    // delay happens once, after the shared queue itself gives up, instead.
    if stayup_on_close {
        let stayup = stayup_after();
        if !stayup.is_zero() {
            log::info!("run_callback_session: STAYUP_AFTER set, sleeping {stayup:?} before closing the stream");
            tokio::time::sleep(stayup).await;
        }
    }

    // Genuinely done now -- close this process's own send side and wait
    // for attestor's ack, same reasoning this step always had: send_data()
    // returning Ok only proves the local kernel accepted the write into
    // its own send buffer, not that attestor actually received it, and
    // this execution environment can have its networking torn down
    // essentially the moment this function returns -- confirmed live: a
    // ~3.6KB response was silently lost in transit this way while a
    // ~100-byte one never was, both reported as a clean local send.
    // attestor's own callback branch explicitly acks (closes its send
    // side) only after it has already seen every byte it's going to
    // read from this stream -- waiting for that here is what turns "my
    // local kernel accepted this write" into "the peer actually has it"
    // before this process is allowed to exit.
    send.send_data(Bytes::new(), true)
        .map_err(|e| SessionError::Protocol(format!("could not close stream: {e}")))?;

    log::info!("run_callback_session: waiting for attestor's ack before returning");
    loop {
        match recv.data().await {
            Some(Ok(chunk)) => {
                let _ = recv.flow_control().release_capacity(chunk.len());
            }
            Some(Err(e)) => {
                return Err(SessionError::Protocol(format!("error waiting for attestor's ack: {e}")));
            }
            None => break,
        }
    }
    log::info!("run_callback_session: got attestor's ack, done");
    Ok(())
}

/// Dials `callback_addr` over h2c and presents `token` at CALLBACK_PATH --
/// used by aci_callback_handler() for every job, whether fulfilling this
/// container's own original launch or rejoining the shared queue (see
/// SHARED_QUEUE_TOKEN_PREFIX's own doc comment, session_protocol.rs).
/// Returns the
/// (send, recv) pair to run a session over, plus the connection-driving
/// task the caller must keep polled/awaited -- NOT tokio::spawn()'d and
/// left fully detached by the caller: send_data() (inside
/// run_callback_session(), via h2_write_frame()) only enqueues onto the
/// stream's own send buffer, and this task is what actually drains that
/// buffer onto the wire, so it has to still be getting polled when that
/// happens (see wait_for_connection_driver()'s own comment for the other
/// half of why this matters) -- confirmed live: an earlier version of
/// this dropped the task at function end and attestor's own callback
/// listener saw the response stream error out ("stream no longer
/// needed") instead of receiving a clean frame.
async fn dial_callback(
    callback_addr: &str,
    token: &str,
) -> Result<(h2::SendStream<Bytes>, h2::RecvStream, tokio::task::JoinHandle<()>), SessionError> {
    log::info!("dial_callback: dialing callback_addr={callback_addr}");
    let tcp = TcpStream::connect(callback_addr)
        .await
        .map_err(|e| SessionError::Protocol(format!("could not connect to {callback_addr}: {e}")))?;
    log::info!("dial_callback: tcp connected, doing h2 handshake");
    let (h2, connection) = h2::client::handshake(tcp)
        .await
        .map_err(|e| SessionError::Protocol(format!("h2 client handshake failed: {e}")))?;
    log::info!("dial_callback: h2 handshake done");
    let connection_task = tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::warn!("h2 callback connection driver error: {e}");
        }
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://{callback_addr}{CALLBACK_PATH}"))
        .header(CALLBACK_TOKEN_HEADER, token)
        .body(())
        .map_err(|e| SessionError::Protocol(format!("could not build callback request: {e}")))?;

    let mut ready = h2
        .ready()
        .await
        .map_err(|e| SessionError::Protocol(format!("h2 connection not ready: {e}")))?;
    log::info!("dial_callback: h2 ready, sending callback request with token={token}");
    let (response, send) = ready
        .send_request(request, false)
        .map_err(|e| SessionError::Protocol(format!("could not send callback request: {e}")))?;
    // No more streams will ever be opened on this connection -- one
    // callback, one request/response, always. Dropping this handle now
    // (rather than only at function end) tells the h2 client that; once
    // our one stream's data is flushed, the connection has nothing left
    // to stay open for and connection_task completes on its own instead
    // of needing an external timeout+abort to end it, which was exactly
    // the race that dropped larger responses before they fully flushed
    // (confirmed live: this failed specifically for responses too big to
    // fit the first send_data() poll, never for tiny ones).
    drop(ready);
    log::info!("dial_callback: callback request sent, awaiting response headers");
    let response = response
        .await
        .map_err(|e| SessionError::Protocol(format!("callback request failed: {e}")))?;
    log::info!("dial_callback: got response headers, status={}", response.status());
    if !response.status().is_success() {
        return Err(SessionError::Protocol(format!("callback listener returned {}", response.status())));
    }
    let (_head, recv) = response.into_parts();

    Ok((send, recv, connection_task))
}

/// With `h2` already dropped in dial_callback(), the connection task
/// normally finishes on its own once the final frame is actually on the
/// wire -- this wait is a generous safety net against a peer that never
/// sends its own GOAWAY, not the primary mechanism for making sure data
/// flushed.
async fn wait_for_connection_driver(mut connection_task: tokio::task::JoinHandle<()>) {
    match tokio::time::timeout(Duration::from_secs(10), &mut connection_task).await {
        Ok(join_result) => log::info!("connection driver finished on its own: {join_result:?}"),
        Err(_) => {
            log::warn!("connection driver still running after 10s, aborting it");
            connection_task.abort();
        }
    }
}

/// The handshake half of the ACI build's own protocol -- reads the real
/// client's public key, gets real MAA evidence, sends the container_hello
/// back, and derives the session key. Split out from aci_callback_handler()
/// so its caller can catch a failure here specifically and report it back
/// over the wire (see that function's own comment on why) before this
/// process exits -- a torn-down-after-one-session ACI container has no
/// other place a human could go looking for this once it's gone.
#[cfg(feature = "aci-attestation")]
async fn aci_handshake(
    send: &mut h2::SendStream<Bytes>,
    recv: &mut h2::RecvStream,
) -> Result<[u8; 32], SessionError> {
    // attested_session.rs forwards the real client's own client_hello key
    // here once it has matched this connection to the pending session it
    // registered before launching this container group -- see that
    // module's own new ACI branch for the other half of this exchange.
    log::info!("aci_callback_handler: reading client_public_key frame");
    let hello_frame = h2_read_frame(recv).await?;
    let hello: serde_json::Value = serde_json::from_slice(&hello_frame)?;
    let client_public_key_b64 = hello
        .get("client_public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SessionError::Protocol("callback hello missing client_public_key".to_string()))?;
    let client_public_key_bytes = general_purpose::STANDARD.decode(client_public_key_b64)?;
    let client_public_key = PublicKey::from_sec1_bytes(&client_public_key_bytes)
        .map_err(|e| SessionError::Protocol(format!("invalid client_public_key: {e}")))?;
    let client_public_key_hash = binding_hash(&client_public_key_bytes);
    // The real client's own comma-separated options string (routing/billing
    // -- see attested_session.rs's own handle_connection() for where this
    // originates), forwarded here unchanged inside the same frame
    // client_public_key rides in. This process is where options actually
    // get resolved once real environment/billing dispatch exists; for now
    // there is nothing to resolve, so what goes into the attested binding
    // and what comes back in container_hello are the same string the
    // client sent. Missing entirely (an older attested_session.rs) reads
    // as "", the same as an explicitly empty options string -- no options
    // requested and no options resolved are the same claim either way.
    let options = hello.get("options").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // ATTESTER_MOCK_ATTESTATION: same flag, same "never in production, an
    // empty/placeholder document is not attestation evidence" posture
    // attestation.rs's own Nitro/Azure-guest mock mode already documents
    // -- mirrored here rather than reused directly since this build has
    // no real SEV-SNP/MAA hardware to fall back to on a host that isn't
    // one (a laptop, a plain container runtime), unlike Nitro/Azure guest
    // attestation's own always-available real path. Only skips
    // get_maa_token() itself -- the real ECDH/session-key derivation
    // below still runs for real either way, so the rest of the wire
    // protocol (framing, AEAD, worker dispatch) is still genuinely
    // exercised. aci_executor.rs's own verify_maa_token() has the
    // matching bypass on attester-service's side; aci_executor.rs's own
    // launch() is what actually propagates this flag into the launched
    // container's env in the first place -- this process never reads it
    // from anywhere else.
    let maa_token = if mock_attestation_enabled() {
        log::warn!("aci_callback_handler: ATTESTER_MOCK_ATTESTATION set -- skipping real MAA attestation");
        MOCK_MAA_TOKEN.to_string()
    } else {
        log::info!("aci_callback_handler: getting a real MAA token");
        let http_client = reqwest::Client::new();
        aci_attestation::get_maa_token(&http_client, &client_public_key_hash, &options).await?
    };

    let ephemeral_secret = SecretKey::random(&mut rand::thread_rng());
    let ephemeral_public_bytes = ephemeral_secret.public_key().to_sec1_bytes();

    // attested_session.rs verifies this itself before ever relaying it to
    // the real client as that client's own server_hello -- this process
    // never talks to the real client directly, only to attester-service's
    // callback listener.
    let container_hello = serde_json::json!({
        "ephemeral_public_key": general_purpose::STANDARD.encode(&ephemeral_public_bytes),
        "attestation_document": general_purpose::STANDARD.encode(maa_token.as_bytes()),
        "options": options,
    });
    h2_write_frame(send, serde_json::to_vec(&container_hello)?.as_slice(), false)?;

    Ok(derive_session_key(&ephemeral_secret, &client_public_key))
}

/// Runs one job to completion on an already-dialed callback connection:
/// aci_handshake() (bounded by `handshake_timeout` when given -- see the
/// shared-queue loop below, `None` for an ordinary launch-fulfilling
/// dial where there's always exactly one job waiting already) then
/// run_callback_session(), which closes the stream itself once it's done
/// (see that function's own doc comment) -- this function never has to.
/// A handshake failure is reported back over the wire the same way
/// regardless of which token got this connection open (a real
/// ACI_CALLBACK_TOKEN, or SHARED_QUEUE_TOKEN_PREFIX -- see that
/// constant's own doc comment): confirmed live, an error that just
/// propagates and lets `send`/`recv` drop unclosed shows up on
/// attested_session.rs's own side as an opaque h2 "stream no longer
/// needed", giving no way to tell a config problem from an attestation
/// rejection from anything else.
#[cfg(feature = "aci-attestation")]
async fn run_one_dialed_session(
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    callback_addr: &str,
    handshake_timeout: Option<Duration>,
    stayup_on_close: bool,
) -> Result<(), SessionError> {
    let handshake_result = match handshake_timeout {
        None => aci_handshake(&mut send, &mut recv).await,
        Some(timeout) => match tokio::time::timeout(timeout, aci_handshake(&mut send, &mut recv)).await {
            Ok(result) => result,
            Err(_elapsed) => {
                return Err(SessionError::Protocol(format!(
                    "no job within {timeout:?} of joining the shared queue"
                )))
            }
        },
    };
    let session_key = match handshake_result {
        Ok(key) => key,
        Err(e) => {
            log::error!("aci_handshake failed: {e}");
            let error_frame = serde_json::json!({ "type": "error", "message": e.to_string() });
            if let Ok(bytes) = serde_json::to_vec(&error_frame) {
                if let Err(send_err) = h2_write_frame(&mut send, &bytes, true) {
                    log::warn!("could not report handshake failure back over the wire: {send_err}");
                }
            }
            return Err(e);
        }
    };
    run_callback_session(session_key, callback_addr, send, recv, stayup_on_close).await
}

#[cfg(feature = "aci-attestation")]
async fn aci_callback_handler() -> Result<(), SessionError> {
    let callback_addr = env_or("ACI_CALLBACK_ADDR", "");
    if callback_addr.is_empty() {
        return Err(SessionError::Protocol("ACI_CALLBACK_ADDR is not set".to_string()));
    }
    let token = env_or("ACI_CALLBACK_TOKEN", "");
    if token.is_empty() {
        return Err(SessionError::Protocol("ACI_CALLBACK_TOKEN is not set".to_string()));
    }

    // The job this container was actually launched for -- unchanged from
    // before shared-worker mode existed, and still the only job an
    // ordinary (non-shared) container ever runs. stayup_on_close is
    // `!is_shared_worker()`: for an ordinary container this close is what
    // gets it torn down, so STAYUP_AFTER's debug window belongs here; a
    // shared worker instead gets that window later, once it actually
    // gives up on the queue (see the loop below) -- not after every
    // individual job it happens to run first.
    let is_shared = is_shared_worker();
    let (send, recv, connection_task) = dial_callback(&callback_addr, &token).await?;
    let session_result = run_one_dialed_session(send, recv, &callback_addr, None, !is_shared).await;
    log::info!("aci_callback_handler: first job returned {session_result:?}, waiting on connection driver");
    wait_for_connection_driver(connection_task).await;
    session_result?;

    if !is_shared {
        return Ok(());
    }

    // Shared-worker mode: this container already did the one job it was
    // launched for; now it offers itself for more, one job at a time,
    // over a fresh connection each time -- see SHARED_QUEUE_TOKEN_PREFIX's
    // own doc comment for why a fresh dial rather than reusing this same
    // stream (the short version: it keeps "this job is over" an ordinary
    // stream close, exactly as it's always been, instead of inventing a
    // second, in-band way to say the same thing). attested_session.rs's
    // own SharedWorkerPool is the other half: it holds this connection
    // idle, tagged by worker_execution_options(), and bridges a matching
    // future client onto it instead of paying for a fresh container-group
    // launch.
    let idle_timeout = shared_worker_idle_timeout();
    // ACI_GROUP_NAME: this container's own group name, injected at launch
    // by aci_executor.rs's own create_group_body() -- the only way this
    // process ever learns it, since it mints nothing itself. Empty here
    // means an attester-service build that predates this env var; the
    // pool entry attested_session.rs would build from that has nothing
    // to tear down with, so it's better to fail the rejoin loudly than
    // silently leak a container group -- see the "aborting" log below.
    let group_name = env_or("ACI_GROUP_NAME", "");
    if group_name.is_empty() {
        log::warn!("aci_callback_handler: ACI_GROUP_NAME is not set, cannot safely join the shared queue");
        return Ok(());
    }
    let shared_token = format!("{SHARED_QUEUE_TOKEN_PREFIX}{group_name}:{}", worker_execution_options());
    let mut jobs_run: u32 = 1;
    loop {
        log::info!(
            "aci_callback_handler: joining shared queue for job {}, waiting up to {idle_timeout:?}",
            jobs_run + 1
        );
        let (send, recv, connection_task) = match dial_callback(&callback_addr, &shared_token).await {
            Ok(triple) => triple,
            Err(e) => {
                log::warn!("aci_callback_handler: could not join shared queue: {e}");
                return Ok(());
            }
        };
        // false: an ordinary shared-queue job's own close never tears
        // this container down (attested_session.rs expects a rejoin), so
        // sleeping here would just slow down every job in the queue for
        // no debugging benefit. The one delay this loop owes STAYUP_AFTER
        // fires below, once, at the point the queue wait actually times
        // out and this container is genuinely done for good.
        let job_result = run_one_dialed_session(send, recv, &callback_addr, Some(idle_timeout), false).await;
        log::info!("aci_callback_handler: shared-queue job returned {job_result:?}, waiting on connection driver");
        wait_for_connection_driver(connection_task).await;
        match job_result {
            Ok(()) => jobs_run += 1,
            Err(e) => {
                log::info!(
                    "aci_callback_handler: shared-queue wait ended ({e}), closing after {jobs_run} job(s)"
                );
                let stayup = stayup_after();
                if !stayup.is_zero() {
                    log::info!(
                        "aci_callback_handler: STAYUP_AFTER set, sleeping {stayup:?} before exiting"
                    );
                    tokio::time::sleep(stayup).await;
                }
                return Ok(());
            }
        }
    }
}

#[cfg(feature = "aci-attestation")]
async fn run_aci_callback_mode() {
    log::info!("session-master (aci-attestation build) starting");
    if let Err(e) = aci_callback_handler().await {
        log::error!("aci session failed: {e}");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    if bwrap_available().await {
        log::info!("bubblewrap self-test passed at startup -- worker.py will run sandboxed");
    } else {
        log::warn!(
            "bubblewrap self-test (`bwrap ... -- true`) failed on this host -- \
             falling back to running worker.py unsandboxed. Current goal is reaching \
             attestation, not isolation -- see bwrap_available()'s own doc comment."
        );
    }

    #[cfg(feature = "aci-attestation")]
    run_aci_callback_mode().await;
    // Lambda mode (this binary built without --features aci-attestation)
    // has been removed entirely -- there is no other backend this binary
    // knows how to be anymore. Kept as a build target rather than making
    // aci-attestation non-optional, since Cargo.toml's own `sev` optional
    // dependency (gated on this same feature) is untouched here -- see
    // that file's own comment for why this repo doesn't remove
    // [dependencies] lines without a `cargo`-regenerated Cargo.lock.
    #[cfg(not(feature = "aci-attestation"))]
    {
        log::error!(
            "session_master was built without --features aci-attestation -- \
             Lambda mode has been removed; this binary only supports the ACI build now."
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod worker_bundle_tests {
    // Covers fetch_worker_bundle()'s own cheap, no-network validation --
    // the sha256 shape check and the malformed-grant checks all return
    // before ever touching the network, so they're real unit tests, not
    // integration tests in disguise. The actual fetch-and-verify round
    // trip against a real S3-compatible endpoint isn't covered here:
    // this repo has no lightweight mock-S3 helper (store.rs's own
    // for_test_endpoint(), backend repo, takes a real running endpoint,
    // same convention) -- worth a real integration test as a follow-up,
    // not assumed working from these alone.
    use super::fetch_worker_bundle;

    #[tokio::test]
    async fn rejects_a_sha256_of_the_wrong_length() {
        let grant = serde_json::json!({
            "access_key_id": "a", "secret_access_key": "b",
            "bucket": "c", "endpoint": "https://example.invalid",
        });
        let err = fetch_worker_bundle(&grant, "deadbeef").await.unwrap_err();
        assert!(err.contains("invalid worker_bundle sha256"), "{err}");
    }

    #[tokio::test]
    async fn rejects_a_sha256_with_non_hex_characters() {
        let grant = serde_json::json!({
            "access_key_id": "a", "secret_access_key": "b",
            "bucket": "c", "endpoint": "https://example.invalid",
        });
        let not_hex = "g".repeat(64);
        let err = fetch_worker_bundle(&grant, &not_hex).await.unwrap_err();
        assert!(err.contains("invalid worker_bundle sha256"), "{err}");
    }

    #[tokio::test]
    async fn refuses_before_any_network_call_when_the_grant_is_missing_fields() {
        let valid_hash = "a".repeat(64);
        // No "bucket" at all -- must fail on the grant, not attempt a
        // request with an empty bucket name.
        let grant = serde_json::json!({
            "access_key_id": "a", "secret_access_key": "b",
            "endpoint": "https://example.invalid",
        });
        let err = fetch_worker_bundle(&grant, &valid_hash).await.unwrap_err();
        assert!(err.contains("storage_grant missing bucket"), "{err}");
    }

    /// A pre-existing extracted runtime/runtime file must short-circuit
    /// straight to Ok() -- proven here by using a storage_grant that
    /// would fail the very next check (missing "bucket") if the cache
    /// check were skipped or ordered after grant validation.
    #[tokio::test]
    async fn cache_hit_skips_the_grant_check_and_any_network_call() {
        let hash = "b".repeat(64);
        let extract_dir = std::path::PathBuf::from(format!("/tmp/worker-runtime-{hash}"));
        let entry_point = extract_dir.join("runtime").join("runtime");
        tokio::fs::create_dir_all(entry_point.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&entry_point, b"#!/bin/sh\n")
            .await
            .unwrap();

        let grant_missing_bucket = serde_json::json!({
            "access_key_id": "a", "secret_access_key": "b",
            "endpoint": "https://example.invalid",
        });
        let resolved = fetch_worker_bundle(&grant_missing_bucket, &hash)
            .await
            .expect("cache hit must not touch storage_grant validation at all");
        assert_eq!(resolved, extract_dir.join("runtime"));

        tokio::fs::remove_dir_all(&extract_dir).await.unwrap();
    }
}
