#![cfg(target_os = "linux")]
use codex_core::config::types::ShellEnvironmentPolicy;
use codex_core::error::CodexErr;
use codex_core::error::Result;
use codex_core::error::SandboxErr;
use codex_core::exec::ExecCapturePolicy;
use codex_core::exec::ExecParams;
use codex_core::exec::process_exec_tool_call;
use codex_core::exec_env::create_env;
use codex_core::sandboxing::SandboxPermissions;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_protocol::protocol::ReadOnlyAccess;
use codex_protocol::protocol::SandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use pretty_assertions::assert_eq;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::NamedTempFile;

// At least on GitHub CI, the arm64 tests appear to need longer timeouts.

#[cfg(not(target_arch = "aarch64"))]
const SHORT_TIMEOUT_MS: u64 = 200;
#[cfg(target_arch = "aarch64")]
const SHORT_TIMEOUT_MS: u64 = 5_000;

#[cfg(not(target_arch = "aarch64"))]
const LONG_TIMEOUT_MS: u64 = 1_000;
#[cfg(target_arch = "aarch64")]
const LONG_TIMEOUT_MS: u64 = 5_000;

#[cfg(not(target_arch = "aarch64"))]
const NETWORK_TIMEOUT_MS: u64 = 2_000;
#[cfg(target_arch = "aarch64")]
const NETWORK_TIMEOUT_MS: u64 = 10_000;

const BWRAP_UNAVAILABLE_ERR: &str = "build-time bubblewrap is not available in this build.";

fn create_env_from_core_vars() -> HashMap<String, String> {
    let policy = ShellEnvironmentPolicy::default();
    create_env(&policy, None)
}

/// Single-quote a string for safe use as a shell word.  Handles embedded
/// single-quotes with the `'...''"'"'...'` idiom so paths containing spaces
/// or special characters are passed literally to the shell.
fn shell_quote(s: &str) -> String {
    // Each embedded single-quote is closed, escaped, then reopened: ' → '\''.
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Core execution helper shared by all test helpers.  Builds `ExecParams` once
/// and calls `process_exec_tool_call` so the sandboxing plumbing is exercised
/// identically in every test path.
#[expect(clippy::expect_used)]
async fn exec_sandboxed(
    cmd: &[&str],
    sandbox_policy: SandboxPolicy,
    file_system_sandbox_policy: FileSystemSandboxPolicy,
    network_sandbox_policy: NetworkSandboxPolicy,
    timeout_ms: u64,
    use_legacy_landlock: bool,
) -> Result<codex_core::exec::ExecToolCallOutput> {
    let cwd = std::env::current_dir().expect("current dir should be accessible");
    let params = ExecParams {
        command: cmd.iter().copied().map(str::to_owned).collect(),
        cwd: cwd.clone(),
        expiration: timeout_ms.into(),
        capture_policy: ExecCapturePolicy::ShellTool,
        env: create_env_from_core_vars(),
        network: None,
        sandbox_permissions: SandboxPermissions::UseDefault,
        windows_sandbox_level: WindowsSandboxLevel::Disabled,
        windows_sandbox_private_desktop: false,
        justification: None,
        arg0: None,
    };
    let sandbox_program = env!("CARGO_BIN_EXE_codex-linux-sandbox");
    let codex_linux_sandbox_exe = Some(PathBuf::from(sandbox_program));

    process_exec_tool_call(
        params,
        &sandbox_policy,
        &file_system_sandbox_policy,
        network_sandbox_policy,
        cwd.as_path(),
        &codex_linux_sandbox_exe,
        use_legacy_landlock,
        None,
    )
    .await
}

#[expect(clippy::print_stdout)]
async fn run_cmd(cmd: &[&str], writable_roots: &[PathBuf], timeout_ms: u64) {
    let output = run_cmd_output(cmd, writable_roots, timeout_ms).await;
    if output.exit_code != 0 {
        println!("stdout:\n{}", output.stdout.text);
        println!("stderr:\n{}", output.stderr.text);
        panic!("exit code: {}", output.exit_code);
    }
}

#[expect(clippy::expect_used)]
async fn run_cmd_output(
    cmd: &[&str],
    writable_roots: &[PathBuf],
    timeout_ms: u64,
) -> codex_core::exec::ExecToolCallOutput {
    run_cmd_result_with_writable_roots(cmd, writable_roots, timeout_ms, false, false)
        .await
        .expect("sandboxed command should execute")
}

#[expect(clippy::expect_used)]
async fn run_cmd_result_with_writable_roots(
    cmd: &[&str],
    writable_roots: &[PathBuf],
    timeout_ms: u64,
    use_legacy_landlock: bool,
    network_access: bool,
) -> Result<codex_core::exec::ExecToolCallOutput> {
    let sandbox_policy = SandboxPolicy::WorkspaceWrite {
        writable_roots: writable_roots
            .iter()
            .map(|p| {
                AbsolutePathBuf::try_from(p.as_path())
                    .expect("writable root should be an absolute path")
            })
            .collect(),
        read_only_access: Default::default(),
        network_access,
        // Exclude tmp-related folders from writable roots because we need a
        // folder that is writable by tests but that we intentionally disallow
        // writing to in the sandbox.
        exclude_tmpdir_env_var: true,
        exclude_slash_tmp: true,
    };
    let file_system_sandbox_policy = FileSystemSandboxPolicy::from(&sandbox_policy);
    let network_sandbox_policy = NetworkSandboxPolicy::from(&sandbox_policy);
    run_cmd_result_with_policies(
        cmd,
        sandbox_policy,
        file_system_sandbox_policy,
        network_sandbox_policy,
        timeout_ms,
        use_legacy_landlock,
    )
    .await
}

async fn run_cmd_result_with_policies(
    cmd: &[&str],
    sandbox_policy: SandboxPolicy,
    file_system_sandbox_policy: FileSystemSandboxPolicy,
    network_sandbox_policy: NetworkSandboxPolicy,
    timeout_ms: u64,
    use_legacy_landlock: bool,
) -> Result<codex_core::exec::ExecToolCallOutput> {
    exec_sandboxed(
        cmd,
        sandbox_policy,
        file_system_sandbox_policy,
        network_sandbox_policy,
        timeout_ms,
        use_legacy_landlock,
    )
    .await
}

fn is_bwrap_unavailable_output(output: &codex_core::exec::ExecToolCallOutput) -> bool {
    output.stderr.text.contains(BWRAP_UNAVAILABLE_ERR)
        || (output
            .stderr
            .text
            .contains("Can't mount proc on /newroot/proc")
            && (output.stderr.text.contains("Operation not permitted")
                || output.stderr.text.contains("Permission denied")
                || output.stderr.text.contains("Invalid argument")))
}

async fn should_skip_bwrap_tests() -> bool {
    match run_cmd_result_with_writable_roots(
        &["bash", "-lc", "true"],
        &[],
        NETWORK_TIMEOUT_MS,
        false,
        true,
    )
    .await
    {
        Ok(output) => is_bwrap_unavailable_output(&output),
        Err(CodexErr::Sandbox(SandboxErr::Denied { output, .. })) => {
            is_bwrap_unavailable_output(&output)
        }
        // Probe timeouts are not actionable for the bwrap-specific assertions below;
        // skip rather than fail the whole suite.
        Err(CodexErr::Sandbox(SandboxErr::Timeout { .. })) => true,
        Err(err) => panic!("bwrap availability probe failed unexpectedly: {err:?}"),
    }
}

/// Returns `true` and emits a skip message when the bubblewrap sandbox is
/// unavailable in the current environment.  Tests that require bwrap should
/// call this at the top and `return` immediately if it yields `true`.
async fn skip_if_bwrap_unavailable() -> bool {
    if should_skip_bwrap_tests().await {
        eprintln!("skipping bwrap test: bwrap sandbox prerequisites are unavailable");
        true
    } else {
        false
    }
}

fn expect_denied(
    result: Result<codex_core::exec::ExecToolCallOutput>,
    context: &str,
) -> codex_core::exec::ExecToolCallOutput {
    match result {
        Ok(output) => {
            assert_ne!(
                output.exit_code, 0,
                "{context}: expected nonzero exit code\nstdout:\n{}\nstderr:\n{}",
                output.stdout.text, output.stderr.text
            );
            output
        }
        Err(CodexErr::Sandbox(SandboxErr::Denied { output, .. })) => *output,
        Err(err) => panic!("{context}: unexpected error: {err:?}"),
    }
}

// ─── Basic sandbox tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_root_read() {
    run_cmd(&["ls", "-l", "/bin"], &[], SHORT_TIMEOUT_MS).await;
}

#[tokio::test]
#[should_panic]
async fn test_root_write() {
    let tmpfile = NamedTempFile::new().expect("temp file should be created");
    let tmpfile_path = tmpfile.path().to_string_lossy();
    run_cmd(
        &[
            "bash",
            "-lc",
            &format!("echo blah > {}", shell_quote(&tmpfile_path)),
        ],
        &[],
        SHORT_TIMEOUT_MS,
    )
    .await;
}

// ─── Bubblewrap filesystem tests ─────────────────────────────────────────────

#[tokio::test]
async fn test_dev_null_write() {
    if skip_if_bwrap_unavailable().await {
        return;
    }

    let output = run_cmd_result_with_writable_roots(
        &["bash", "-lc", "echo blah > /dev/null"],
        &[],
        // We have seen timeouts when running this test in CI on GitHub,
        // so we are using a generous timeout until we can diagnose further.
        LONG_TIMEOUT_MS,
        false,
        true,
    )
    .await
    .expect("sandboxed command should execute");

    assert_eq!(output.exit_code, 0);
}

#[tokio::test]
async fn bwrap_populates_minimal_dev_nodes() {
    if skip_if_bwrap_unavailable().await {
        return;
    }

    let output = run_cmd_result_with_writable_roots(
        &[
            "bash",
            "-lc",
            "for node in null zero full random urandom tty; do [ -c \"/dev/$node\" ] || { echo \"missing /dev/$node\" >&2; exit 1; }; done",
        ],
        &[],
        LONG_TIMEOUT_MS,
        false,
        true,
    )
    .await
    .expect("sandboxed command should execute");

    assert_eq!(output.exit_code, 0);
}

#[tokio::test]
async fn bwrap_preserves_writable_dev_shm_bind_mount() {
    if skip_if_bwrap_unavailable().await {
        return;
    }
    if !std::path::Path::new("/dev/shm").exists() {
        eprintln!("skipping bwrap test: /dev/shm is unavailable in this environment");
        return;
    }

    let target_file = match NamedTempFile::new_in("/dev/shm") {
        Ok(file) => file,
        Err(err) => {
            eprintln!("skipping bwrap test: failed to create /dev/shm temp file: {err}");
            return;
        }
    };
    let target_path = target_file.path().to_path_buf();
    std::fs::write(&target_path, "host-before").expect("seed /dev/shm file");

    let output = run_cmd_result_with_writable_roots(
        &[
            "bash",
            "-lc",
            &format!(
                "printf sandbox-after > {}",
                shell_quote(&target_path.to_string_lossy())
            ),
        ],
        &[PathBuf::from("/dev/shm")],
        LONG_TIMEOUT_MS,
        false,
        true,
    )
    .await
    .expect("sandboxed command should execute");

    assert_eq!(output.exit_code, 0);
    assert_eq!(
        std::fs::read_to_string(&target_path).expect("read /dev/shm file"),
        "sandbox-after"
    );
}

#[tokio::test]
async fn test_writable_root() {
    let tmpdir = tempfile::tempdir().expect("temp dir should be created");
    let file_path = tmpdir.path().join("test");
    run_cmd(
        &[
            "bash",
            "-lc",
            &format!("echo blah > {}", shell_quote(&file_path.to_string_lossy())),
        ],
        &[tmpdir.path().to_path_buf()],
        // We have seen timeouts when running this test in CI on GitHub,
        // so we are using a generous timeout until we can diagnose further.
        LONG_TIMEOUT_MS,
    )
    .await;
}

#[tokio::test]
async fn sandbox_ignores_missing_writable_roots_under_bwrap() {
    if skip_if_bwrap_unavailable().await {
        return;
    }

    let tempdir = tempfile::tempdir().expect("tempdir");
    let existing_root = tempdir.path().join("existing");
    let missing_root = tempdir.path().join("missing");
    std::fs::create_dir(&existing_root).expect("create existing root");

    let output = run_cmd_result_with_writable_roots(
        &["bash", "-lc", "printf sandbox-ok"],
        &[existing_root, missing_root],
        LONG_TIMEOUT_MS,
        false,
        true,
    )
    .await
    .expect("sandboxed command should execute");

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout.text, "sandbox-ok");
}

#[tokio::test]
async fn test_no_new_privs_is_enabled() {
    let output = run_cmd_output(
        &["bash", "-lc", "grep '^NoNewPrivs:' /proc/self/status"],
        &[],
        // We have seen timeouts when running this test in CI on GitHub,
        // so we are using a generous timeout until we can diagnose further.
        LONG_TIMEOUT_MS,
    )
    .await;
    let line = output
        .stdout
        .text
        .lines()
        .find(|line| line.starts_with("NoNewPrivs:"))
        .unwrap_or("");
    assert_eq!(line.trim(), "NoNewPrivs:\t1");
}

#[tokio::test]
#[should_panic(expected = "Sandbox(Timeout")]
async fn test_timeout() {
    run_cmd(&["sleep", "2"], &[], 50).await;
}

// ─── Network sandbox tests ────────────────────────────────────────────────────

/// Runs `cmd` under a read-only network-disabled sandbox and asserts that it
/// does NOT succeed.  A missing binary (exit 127) is treated as a skip so the
/// suite remains green on leaner CI images.
async fn assert_network_blocked(cmd: &[&str]) {
    let sandbox_policy = SandboxPolicy::new_read_only_policy();
    let fs_policy = FileSystemSandboxPolicy::from(&sandbox_policy);
    let net_policy = NetworkSandboxPolicy::from(&sandbox_policy);
    let result = exec_sandboxed(
        cmd,
        sandbox_policy,
        fs_policy,
        net_policy,
        NETWORK_TIMEOUT_MS,
        false,
    )
    .await;

    let output = match result {
        Ok(output) => output,
        Err(CodexErr::Sandbox(SandboxErr::Denied { output, .. })) => *output,
        _ => {
            panic!("expected sandbox denied error, got: {result:?}");
        }
    };

    // A missing binary exits with 127 – treat as a skip rather than a pass so
    // the suite stays green on leaner CI images without silently hiding a breach.
    if output.exit_code == 127 {
        eprintln!(
            "skipping network test: binary {:?} not found in sandbox (exit 127)",
            cmd.first().copied().unwrap_or("<unknown>")
        );
        return;
    }

    // If—*and only if*—the command exits 0 we consider the sandbox breached.
    if output.exit_code == 0 {
        panic!(
            "Network sandbox FAILED - {cmd:?} exited 0\nstdout:\n{}\nstderr:\n{}",
            output.stdout.text, output.stderr.text
        );
    }
}

#[tokio::test]
async fn sandbox_blocks_curl() {
    assert_network_blocked(&["curl", "-I", "http://openai.com"]).await;
}

#[tokio::test]
async fn sandbox_blocks_wget() {
    assert_network_blocked(&["wget", "-qO-", "http://openai.com"]).await;
}

#[tokio::test]
async fn sandbox_blocks_ping() {
    // ICMP requires raw socket – should be denied quickly with EPERM.
    assert_network_blocked(&["ping", "-c", "1", "8.8.8.8"]).await;
}

#[tokio::test]
async fn sandbox_blocks_nc() {
    // Zero‑length connection attempt to localhost.
    assert_network_blocked(&["nc", "-z", "127.0.0.1", "80"]).await;
}

// ─── Bubblewrap filesystem isolation tests ───────────────────────────────────

#[tokio::test]
async fn sandbox_blocks_git_and_codex_writes_inside_writable_root() {
    if skip_if_bwrap_unavailable().await {
        return;
    }

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let dot_git = tmpdir.path().join(".git");
    let dot_codex = tmpdir.path().join(".codex");
    std::fs::create_dir_all(&dot_git).expect("create .git");
    std::fs::create_dir_all(&dot_codex).expect("create .codex");

    let git_target = dot_git.join("config");
    let codex_target = dot_codex.join("config.toml");

    let git_output = expect_denied(
        run_cmd_result_with_writable_roots(
            &[
                "bash",
                "-lc",
                &format!(
                    "echo denied > {}",
                    shell_quote(&git_target.to_string_lossy())
                ),
            ],
            &[tmpdir.path().to_path_buf()],
            LONG_TIMEOUT_MS,
            false,
            true,
        )
        .await,
        ".git write should be denied under bubblewrap",
    );

    let codex_output = expect_denied(
        run_cmd_result_with_writable_roots(
            &[
                "bash",
                "-lc",
                &format!(
                    "echo denied > {}",
                    shell_quote(&codex_target.to_string_lossy())
                ),
            ],
            &[tmpdir.path().to_path_buf()],
            LONG_TIMEOUT_MS,
            false,
            true,
        )
        .await,
        ".codex write should be denied under bubblewrap",
    );
    assert_ne!(git_output.exit_code, 0);
    assert_ne!(codex_output.exit_code, 0);
}

#[tokio::test]
async fn sandbox_blocks_codex_symlink_replacement_attack() {
    if skip_if_bwrap_unavailable().await {
        return;
    }

    use std::os::unix::fs::symlink;

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let decoy = tmpdir.path().join("decoy-codex");
    std::fs::create_dir_all(&decoy).expect("create decoy dir");

    let dot_codex = tmpdir.path().join(".codex");
    symlink(&decoy, &dot_codex).expect("create .codex symlink");

    let codex_target = dot_codex.join("config.toml");

    let codex_output = expect_denied(
        run_cmd_result_with_writable_roots(
            &[
                "bash",
                "-lc",
                &format!(
                    "echo denied > {}",
                    shell_quote(&codex_target.to_string_lossy())
                ),
            ],
            &[tmpdir.path().to_path_buf()],
            LONG_TIMEOUT_MS,
            false,
            true,
        )
        .await,
        ".codex symlink replacement should be denied",
    );
    assert_ne!(codex_output.exit_code, 0);
}

#[tokio::test]
async fn sandbox_blocks_explicit_split_policy_carveouts_under_bwrap() {
    if skip_if_bwrap_unavailable().await {
        return;
    }

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let blocked = tmpdir.path().join("blocked");
    std::fs::create_dir_all(&blocked).expect("create blocked dir");
    let blocked_target = blocked.join("secret.txt");
    // These tests bypass the usual legacy-policy bridge, so explicitly keep
    // the sandbox helper binary and minimal runtime paths readable.
    let sandbox_helper_dir = PathBuf::from(env!("CARGO_BIN_EXE_codex-linux-sandbox"))
        .parent()
        .expect("sandbox helper should have a parent")
        .to_path_buf();

    let sandbox_policy = SandboxPolicy::WorkspaceWrite {
        writable_roots: vec![AbsolutePathBuf::try_from(tmpdir.path()).expect("absolute tempdir")],
        read_only_access: Default::default(),
        network_access: true,
        exclude_tmpdir_env_var: true,
        exclude_slash_tmp: true,
    };
    let file_system_sandbox_policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Minimal,
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::try_from(sandbox_helper_dir.as_path())
                    .expect("absolute helper dir"),
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::try_from(tmpdir.path()).expect("absolute tempdir"),
            },
            access: FileSystemAccessMode::Write,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::try_from(blocked.as_path()).expect("absolute blocked dir"),
            },
            access: FileSystemAccessMode::None,
        },
    ]);
    let output = expect_denied(
        run_cmd_result_with_policies(
            &[
                "bash",
                "-lc",
                &format!(
                    "echo denied > {}",
                    shell_quote(&blocked_target.to_string_lossy())
                ),
            ],
            sandbox_policy,
            file_system_sandbox_policy,
            NetworkSandboxPolicy::Enabled,
            LONG_TIMEOUT_MS,
            false,
        )
        .await,
        "explicit split-policy carveout should be denied under bubblewrap",
    );

    assert_ne!(output.exit_code, 0);
}

#[tokio::test]
async fn sandbox_reenables_writable_subpaths_under_unreadable_parents() {
    if skip_if_bwrap_unavailable().await {
        return;
    }

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let blocked = tmpdir.path().join("blocked");
    let allowed = blocked.join("allowed");
    std::fs::create_dir_all(&allowed).expect("create blocked/allowed dir");
    let allowed_target = allowed.join("note.txt");
    // These tests bypass the usual legacy-policy bridge, so explicitly keep
    // the sandbox helper binary and minimal runtime paths readable.
    let sandbox_helper_dir = PathBuf::from(env!("CARGO_BIN_EXE_codex-linux-sandbox"))
        .parent()
        .expect("sandbox helper should have a parent")
        .to_path_buf();

    let sandbox_policy = SandboxPolicy::WorkspaceWrite {
        writable_roots: vec![AbsolutePathBuf::try_from(tmpdir.path()).expect("absolute tempdir")],
        read_only_access: Default::default(),
        network_access: true,
        exclude_tmpdir_env_var: true,
        exclude_slash_tmp: true,
    };
    let file_system_sandbox_policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Minimal,
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::try_from(sandbox_helper_dir.as_path())
                    .expect("absolute helper dir"),
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::try_from(tmpdir.path()).expect("absolute tempdir"),
            },
            access: FileSystemAccessMode::Write,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::try_from(blocked.as_path()).expect("absolute blocked dir"),
            },
            access: FileSystemAccessMode::None,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::try_from(allowed.as_path()).expect("absolute allowed dir"),
            },
            access: FileSystemAccessMode::Write,
        },
    ]);
    let quoted = shell_quote(&allowed_target.to_string_lossy());
    let output = run_cmd_result_with_policies(
        &[
            "bash",
            "-lc",
            &format!("printf allowed > {quoted} && cat {quoted}"),
        ],
        sandbox_policy,
        file_system_sandbox_policy,
        NetworkSandboxPolicy::Enabled,
        LONG_TIMEOUT_MS,
        false,
    )
    .await
    .expect("nested writable carveout should execute under bubblewrap");

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout.text.trim(), "allowed");
}

#[tokio::test]
async fn sandbox_blocks_root_read_carveouts_under_bwrap() {
    if skip_if_bwrap_unavailable().await {
        return;
    }

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let blocked = tmpdir.path().join("blocked");
    std::fs::create_dir_all(&blocked).expect("create blocked dir");
    let blocked_target = blocked.join("secret.txt");
    std::fs::write(&blocked_target, "secret").expect("seed blocked file");

    let sandbox_policy = SandboxPolicy::ReadOnly {
        access: ReadOnlyAccess::FullAccess,
        network_access: true,
    };
    let file_system_sandbox_policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::try_from(blocked.as_path()).expect("absolute blocked dir"),
            },
            access: FileSystemAccessMode::None,
        },
    ]);
    let output = expect_denied(
        run_cmd_result_with_policies(
            &[
                "bash",
                "-lc",
                &format!("cat {}", shell_quote(&blocked_target.to_string_lossy())),
            ],
            sandbox_policy,
            file_system_sandbox_policy,
            NetworkSandboxPolicy::Enabled,
            LONG_TIMEOUT_MS,
            false,
        )
        .await,
        "root-read carveout should be denied under bubblewrap",
    );

    assert_ne!(output.exit_code, 0);
}

#[tokio::test]
async fn sandbox_blocks_ssh() {
    // Force ssh to attempt a real TCP connection but fail quickly.  `BatchMode`
    // avoids password prompts, and `ConnectTimeout` keeps the hang time low.
    assert_network_blocked(&[
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=1",
        "github.com",
    ])
    .await;
}

#[tokio::test]
async fn sandbox_blocks_getent() {
    assert_network_blocked(&["getent", "ahosts", "openai.com"]).await;
}

#[tokio::test]
async fn sandbox_blocks_dev_tcp_redirection() {
    // This syntax is only supported by bash and zsh. We try bash first.
    // Fallback generic socket attempt using /bin/sh with bash‑style /dev/tcp.  Not
    // all images ship bash, so we guard against 127 as well.
    assert_network_blocked(&["bash", "-c", "echo hi > /dev/tcp/127.0.0.1/80"]).await;
}
