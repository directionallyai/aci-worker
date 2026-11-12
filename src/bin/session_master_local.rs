//! session_master_local: the worker half of aci-worker with the attestation
//! taken out, for running inside an emulator (e.g. a Cartesi machine) or on
//! a laptop.
//!
//! **UNATTESTED. DEV ONLY.** Nothing here proves what code is running or
//! where. There is no SEV-SNP report, no MAA token, no ECDH session and no
//! encryption: requests arrive as plaintext on a TCP port, and they carry
//! `content_keys` and a `storage_grant`. Whoever can reach the port (and
//! whoever runs the machine) can read both. Run it only against data and
//! credentials you would be happy for that operator to see.
//!
//! What it does, per connection: read one frame, run the worker on it, write
//! one frame back, close.
//!
//!   frame    = u32 big-endian length, then that many bytes (the same
//!              framing `session_protocol::read_frame` uses, with a size cap)
//!   request  = the JSON object worker.py reads on stdin
//!   response = the JSON object worker.py writes on stdout, or
//!              `{"ok": false, "error": ...}` when the worker could not run
//!
//! What it deliberately does not do, compared with `session_master`:
//!   - no callback dial-out, attestation handshake or session encryption;
//!   - no worker_bundle fetch: the runtime is a directory on this machine
//!     (`LOCAL_RUNTIME_DIR`, laid out like worker-python-runtime's tarball,
//!     with an executable `runtime` entry point), so it can be built for the
//!     machine's own CPU architecture. A `worker_bundle` field in a request
//!     is ignored;
//!   - no tail calls: `queue_addr`/`queue_token` are never injected, so
//!     `queue_eval` inside the worker is its own "not available" stand-in
//!     and anything that relies on it (such as the scheduled reviewer) does
//!     nothing here;
//!   - no `local` callback channel (same reason).
//!
//! Configuration (environment):
//!   LOCAL_RUNTIME_DIR           required; directory containing `runtime`
//!   LOCAL_LISTEN                default 127.0.0.1:8700
//!   LOCAL_WORKER_TIMEOUT_SECS   default 300
//!   LOCAL_MAX_CONCURRENT        default 4
//!   LOCAL_MAX_FRAME_BYTES       default 67108864 (64 MiB)
//!   LOCAL_SANDBOX               `bwrap` (default) or `none`. `none` must be
//!                               asked for by name: a machine that cannot
//!                               provide bubblewrap fails closed instead of
//!                               silently running the worker unconfined,
//!                               the same stance `session_master` takes.
//!   WORKER_UID / WORKER_GID     default 10001 (bwrap only)
//!   LOCAL_WARM_SOCKET           optional path of a unix socket served by
//!                               warm_server.py (kept in local-vm-worker). When set, requests
//!                               are handed to that warm process (which
//!                               forks one child per request) instead of
//!                               starting a fresh interpreter each time.
//!                               The children are plain forks, so this
//!                               mode requires LOCAL_SANDBOX=none.

// This binary must never end up in an attested build.
#[cfg(feature = "aci-attestation")]
compile_error!(
    "session_master_local is the UNATTESTED dev binary: do not enable it together with `aci-attestation`"
);

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::process::Command;
use tokio::sync::Semaphore;

const DEFAULT_LISTEN: &str = "127.0.0.1:8700";
const DEFAULT_TIMEOUT_SECS: f64 = 300.0;
const DEFAULT_MAX_CONCURRENT: usize = 4;
const DEFAULT_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
/// A connection that sends nothing for this long is dropped.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sandbox {
    Bwrap,
    None,
}

#[derive(Clone, Debug)]
struct Config {
    runtime_dir: PathBuf,
    listen: String,
    timeout: Duration,
    max_concurrent: usize,
    max_frame_bytes: usize,
    sandbox: Sandbox,
    uid: u32,
    gid: u32,
    warm_socket: Option<PathBuf>,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn parse_sandbox(value: &str) -> Result<Sandbox, String> {
    match value {
        "bwrap" => Ok(Sandbox::Bwrap),
        "none" => Ok(Sandbox::None),
        other => Err(format!(
            "LOCAL_SANDBOX must be `bwrap` or `none`, got `{other}`"
        )),
    }
}

impl Config {
    fn from_env() -> Result<Config, String> {
        let runtime_dir = env_or("LOCAL_RUNTIME_DIR", "");
        if runtime_dir.is_empty() {
            return Err("LOCAL_RUNTIME_DIR is not set".to_string());
        }
        let sandbox = parse_sandbox(&env_or("LOCAL_SANDBOX", "bwrap"))?;
        let warm_socket = Some(env_or("LOCAL_WARM_SOCKET", ""))
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        if warm_socket.is_some() && sandbox != Sandbox::None {
            return Err(
                "LOCAL_WARM_SOCKET requires LOCAL_SANDBOX=none: the warm worker forks plain \
                 children, so there is no sandbox to apply"
                    .to_string(),
            );
        }
        Ok(Config {
            runtime_dir: PathBuf::from(runtime_dir),
            listen: env_or("LOCAL_LISTEN", DEFAULT_LISTEN),
            timeout: Duration::from_secs_f64(
                env_or("LOCAL_WORKER_TIMEOUT_SECS", "")
                    .parse::<f64>()
                    .ok()
                    .filter(|s| *s > 0.0)
                    .unwrap_or(DEFAULT_TIMEOUT_SECS),
            ),
            max_concurrent: env_or("LOCAL_MAX_CONCURRENT", "")
                .parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .unwrap_or(DEFAULT_MAX_CONCURRENT),
            max_frame_bytes: env_or("LOCAL_MAX_FRAME_BYTES", "")
                .parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .unwrap_or(DEFAULT_MAX_FRAME_BYTES),
            sandbox,
            uid: env_or("WORKER_UID", "10001").parse().unwrap_or(10001),
            gid: env_or("WORKER_GID", "10001").parse().unwrap_or(10001),
            warm_socket,
        })
    }

    fn entry_point(&self) -> PathBuf {
        self.runtime_dir.join("runtime")
    }
}

fn worker_failure(message: &str) -> Value {
    json!({ "ok": false, "result": null, "error": message, "stdout": "" })
}

/// The runtime must exist before we start listening: a machine that cannot
/// run its own worker has nothing to offer a caller.
fn check_runtime(config: &Config) -> Result<(), String> {
    let entry = config.entry_point();
    let meta =
        std::fs::metadata(&entry).map_err(|e| format!("{} is not usable: {e}", entry.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", entry.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(format!("{} is not executable", entry.display()));
        }
    }
    Ok(())
}

async fn bwrap_self_test() -> bool {
    matches!(
        Command::new("bwrap")
            .arg("--unshare-all")
            .arg("--share-net")
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--dev")
            .arg("/dev")
            .arg("--ro-bind")
            .arg("/usr")
            .arg("/usr")
            .arg("--")
            .arg("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await,
        Ok(status) if status.success()
    )
}

/// Reads one frame (u32 BE length + payload), refusing anything over `max`
/// before allocating for it.
async fn read_frame_capped<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    max: usize,
) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("could not read frame length: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(format!("frame of {len} bytes exceeds the {max} byte limit"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("could not read frame body: {e}"))?;
    Ok(buf)
}

async fn write_frame<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    payload: &[u8],
) -> std::io::Result<()> {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Only these request fields reach the worker's stdin untouched; the two
/// that `session_master` injects for tail calls and the local callback are
/// stripped so a caller cannot point the worker at a socket of its choosing.
fn sanitize_request(mut request: Value) -> Value {
    if let Some(object) = request.as_object_mut() {
        for field in ["queue_addr", "queue_token", "callback_addr"] {
            object.remove(field);
        }
    }
    request
}

fn build_command(config: &Config, entry: &Path) -> Command {
    let mut command = Command::new("timeout");
    command
        .arg("-s")
        .arg("9")
        .arg("-k")
        .arg("5")
        .arg(config.timeout.as_secs().max(1).to_string());
    match config.sandbox {
        Sandbox::None => {
            command.arg(entry);
        }
        Sandbox::Bwrap => {
            let runtime = config.runtime_dir.to_string_lossy().into_owned();
            command
                .arg("bwrap")
                .arg("--unshare-all")
                .arg("--share-net")
                .arg("--die-with-parent")
                .arg("--new-session")
                .arg("--dev")
                .arg("/dev")
                .arg("--ro-bind")
                .arg("/bin")
                .arg("/bin")
                .arg("--ro-bind")
                .arg("/usr")
                .arg("/usr")
                .arg("--ro-bind")
                .arg("/lib")
                .arg("/lib")
                .arg("--ro-bind-try")
                .arg("/lib64")
                .arg("/lib64")
                .arg("--ro-bind-try")
                .arg("/etc/ssl")
                .arg("/etc/ssl")
                .arg("--ro-bind-try")
                .arg("/etc/resolv.conf")
                .arg("/etc/resolv.conf")
                .arg("--ro-bind-try")
                .arg("/etc/hosts")
                .arg("/etc/hosts")
                .arg("--tmpfs")
                .arg("/tmp")
                .arg("--chmod")
                .arg("1777")
                .arg("/tmp")
                .arg("--setenv")
                .arg("PYTHONDONTWRITEBYTECODE")
                .arg("1")
                .arg("--uid")
                .arg(config.uid.to_string())
                .arg("--gid")
                .arg(config.gid.to_string())
                .arg("--ro-bind")
                .arg(&runtime)
                .arg(&runtime)
                .arg("--")
                .arg(entry);
        }
    }
    command
}

/// Hands the request to the warm worker over its unix socket and returns its
/// framed answer. A missing socket is an error, not a reason to quietly start
/// a cold interpreter: the operator asked for warm mode.
async fn run_warm(config: &Config, socket: &Path, payload: &[u8]) -> Value {
    // The worker enforces its own limit with an alarm; this is the backstop
    // for a worker that never answers.
    let deadline = config.timeout + Duration::from_secs(10);
    let exchange = async {
        let mut stream = UnixStream::connect(socket).await.map_err(|e| {
            format!(
                "could not reach the warm worker at {}: {e}",
                socket.display()
            )
        })?;
        write_frame(&mut stream, payload)
            .await
            .map_err(|e| format!("could not send the request to the warm worker: {e}"))?;
        read_frame_capped(&mut stream, config.max_frame_bytes).await
    };
    match tokio::time::timeout(deadline, exchange).await {
        Ok(Ok(frame)) => serde_json::from_slice::<Value>(&frame)
            .unwrap_or_else(|e| worker_failure(&format!("malformed warm worker response: {e}"))),
        Ok(Err(e)) => worker_failure(&e),
        Err(_) => worker_failure(&format!("warm worker did not answer within {deadline:?}")),
    }
}

async fn run_worker(config: &Config, request: Value) -> Value {
    let payload = match serde_json::to_vec(&sanitize_request(request)) {
        Ok(p) => p,
        Err(e) => return worker_failure(&format!("could not serialize request: {e}")),
    };
    if let Some(socket) = &config.warm_socket {
        return run_warm(config, socket, &payload).await;
    }
    let entry = config.entry_point();
    let mut child = match build_command(config, &entry)
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
    let output = match tokio::time::timeout(config.timeout, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return worker_failure(&format!("worker subprocess error: {e}")),
        Err(_) => return worker_failure(&format!("worker timed out after {:?}", config.timeout)),
    };
    if !output.status.success() {
        return worker_failure(&format!(
            "worker subprocess exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    match serde_json::from_slice::<Value>(&output.stdout) {
        Ok(v) => v,
        Err(e) => worker_failure(&format!(
            "malformed worker response: {e} (stdout: {}, stderr: {})",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )),
    }
}

async fn handle_connection(config: Arc<Config>, mut stream: TcpStream) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let frame = match tokio::time::timeout(
        READ_TIMEOUT,
        read_frame_capped(&mut stream, config.max_frame_bytes),
    )
    .await
    {
        Ok(Ok(frame)) => frame,
        Ok(Err(e)) => {
            log::warn!("{peer}: {e}");
            let _ = write_frame(&mut stream, worker_failure(&e).to_string().as_bytes()).await;
            return;
        }
        Err(_) => {
            log::warn!("{peer}: no request within {READ_TIMEOUT:?}");
            return;
        }
    };
    let response = match serde_json::from_slice::<Value>(&frame) {
        Ok(request) if request.is_object() => run_worker(&config, request).await,
        Ok(_) => worker_failure("request must be a JSON object"),
        Err(e) => worker_failure(&format!("request is not valid JSON: {e}")),
    };
    log::info!(
        "{peer}: ok={}",
        response.get("ok").and_then(Value::as_bool).unwrap_or(false)
    );
    if let Err(e) = write_frame(&mut stream, response.to_string().as_bytes()).await {
        log::warn!("{peer}: could not write response: {e}");
    }
    let _ = stream.shutdown().await;
}

async fn serve(config: Config, listener: TcpListener) {
    let config = Arc::new(config);
    let slots = Arc::new(Semaphore::new(config.max_concurrent));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                log::warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Wait for a free slot before taking the next connection, so a burst
        // queues in the kernel backlog instead of spawning unbounded workers.
        let permit = match slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let config = config.clone();
        tokio::spawn(async move {
            handle_connection(config, stream).await;
            drop(permit);
        });
    }
}

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            log::error!("{e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = check_runtime(&config) {
        log::error!("{e}");
        std::process::exit(2);
    }
    if config.sandbox == Sandbox::Bwrap && !bwrap_self_test().await {
        log::error!(
            "bubblewrap is unavailable here; refusing to run the worker unsandboxed. \
             Set LOCAL_SANDBOX=none to run it without a sandbox on purpose."
        );
        std::process::exit(2);
    }
    let listener = match TcpListener::bind(&config.listen).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("could not listen on {}: {e}", config.listen);
            std::process::exit(2);
        }
    };
    log::warn!(
        "UNATTESTED dev worker listening on {} (sandbox: {:?}). Requests are plaintext and carry keys; \
         nothing here is attested.",
        config.listen,
        config.sandbox
    );
    serve(config, listener).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn test_config(dir: &Path, sandbox: Sandbox) -> Config {
        Config {
            runtime_dir: dir.to_path_buf(),
            listen: "127.0.0.1:0".to_string(),
            timeout: Duration::from_secs(5),
            max_concurrent: 2,
            max_frame_bytes: 1024,
            sandbox,
            uid: 10001,
            gid: 10001,
            warm_socket: None,
        }
    }

    fn fake_runtime(script: &str) -> tempdir::Dir {
        let dir = tempdir::Dir::new();
        let entry = dir.path().join("runtime");
        std::fs::write(&entry, script).unwrap();
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    /// Minimal temp dir, so the tests need no extra dev-dependency.
    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct Dir(PathBuf);
        impl Dir {
            pub fn new() -> Dir {
                let path = std::env::temp_dir().join(format!("sml-test-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir_all(&path).unwrap();
                Dir(path)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    async fn roundtrip(config: Config, request: &[u8]) -> Value {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(config, listener));
        let mut client = TcpStream::connect(addr).await.unwrap();
        write_frame(&mut client, request).await.unwrap();
        let len = {
            let mut b = [0u8; 4];
            client.read_exact(&mut b).await.unwrap();
            u32::from_be_bytes(b) as usize
        };
        let mut body = vec![0u8; len];
        client.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn sandbox_setting_accepts_only_the_two_names() {
        assert_eq!(parse_sandbox("bwrap"), Ok(Sandbox::Bwrap));
        assert_eq!(parse_sandbox("none"), Ok(Sandbox::None));
        assert!(parse_sandbox("").is_err());
        assert!(parse_sandbox("off").is_err());
    }

    #[test]
    fn injected_channel_fields_are_stripped_and_the_rest_kept() {
        let request = json!({
            "mode": "eval", "code": "1", "queue_addr": "x", "queue_token": "y",
            "callback_addr": "z", "content_keys": []
        });
        let cleaned = sanitize_request(request);
        assert_eq!(
            cleaned,
            json!({"mode": "eval", "code": "1", "content_keys": []})
        );
    }

    #[test]
    fn a_missing_or_non_executable_runtime_is_refused() {
        let dir = tempdir::Dir::new();
        assert!(check_runtime(&test_config(dir.path(), Sandbox::None)).is_err());
        std::fs::write(dir.path().join("runtime"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            dir.path().join("runtime"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(check_runtime(&test_config(dir.path(), Sandbox::None))
            .unwrap_err()
            .contains("not executable"));
    }

    #[tokio::test]
    async fn a_request_goes_to_the_worker_and_its_answer_comes_back() {
        // The fake worker echoes the mode it was given, proving the request
        // reached its stdin and that queue fields were removed on the way.
        let dir = fake_runtime(
            "#!/bin/sh\npython3 -c 'import json,sys; r=json.load(sys.stdin); \
             print(json.dumps({\"ok\": True, \"result\": r[\"mode\"], \"queue\": \"queue_addr\" in r}))'\n",
        );
        let response = roundtrip(
            test_config(dir.path(), Sandbox::None),
            br#"{"mode":"eval","code":"1","queue_addr":"127.0.0.1:1"}"#,
        )
        .await;
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["result"], "eval");
        assert_eq!(response["queue"], false);
    }

    #[tokio::test]
    async fn a_worker_that_fails_comes_back_as_an_error_not_a_hang() {
        let dir = fake_runtime("#!/bin/sh\necho boom >&2\nexit 3\n");
        let response = roundtrip(
            test_config(dir.path(), Sandbox::None),
            br#"{"mode":"eval"}"#,
        )
        .await;
        assert_eq!(response["ok"], false);
        assert!(
            response["error"].as_str().unwrap().contains("boom"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn garbage_and_non_object_requests_are_refused() {
        let dir = fake_runtime("#!/bin/sh\necho '{}'\n");
        let response = roundtrip(test_config(dir.path(), Sandbox::None), b"not json").await;
        assert_eq!(response["ok"], false);
        let response = roundtrip(test_config(dir.path(), Sandbox::None), b"[1,2]").await;
        assert!(response["error"].as_str().unwrap().contains("JSON object"));
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_before_it_is_read() {
        let dir = fake_runtime("#!/bin/sh\necho '{}'\n");
        let response = roundtrip(test_config(dir.path(), Sandbox::None), &vec![b' '; 2048]).await;
        assert_eq!(response["ok"], false);
        assert!(
            response["error"].as_str().unwrap().contains("exceeds"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn warm_mode_proxies_the_frame_to_the_unix_socket() {
        let dir = tempdir::Dir::new();
        let socket = dir.path().join("warm.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let frame = read_frame_capped(&mut conn, 1024).await.unwrap();
            let request: Value = serde_json::from_slice(&frame).unwrap();
            // Echo what arrived, so the test can see the request was sanitized.
            let answer = json!({"ok": true, "result": request["code"], "queue": request.get("queue_token").is_some()});
            write_frame(&mut conn, answer.to_string().as_bytes())
                .await
                .unwrap();
        });
        let mut config = test_config(dir.path(), Sandbox::None);
        config.warm_socket = Some(socket);
        let response = run_worker(
            &config,
            json!({"mode": "eval", "code": "6*7", "queue_token": "t"}),
        )
        .await;
        assert_eq!(
            response,
            json!({"ok": true, "result": "6*7", "queue": false})
        );
    }

    #[tokio::test]
    async fn warm_mode_with_no_socket_is_an_error_not_a_cold_start() {
        let dir = tempdir::Dir::new();
        let mut config = test_config(dir.path(), Sandbox::None);
        config.warm_socket = Some(dir.path().join("absent.sock"));
        let response = run_worker(&config, json!({"mode": "eval"})).await;
        assert_eq!(response["ok"], false);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("could not reach the warm worker"),
            "{response}"
        );
    }
}
