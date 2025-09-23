#!/usr/bin/env python3
import base64
import concurrent.futures as cf
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
 

import requests
import threading
import time
import random
import tempfile
import shlex

AZDO_ORG_URL = os.environ.get("AZDO_ORG_URL", "").rstrip("/")
AZDO_PROJECT = os.environ.get("AZDO_PROJECT", "")
AZDO_PAT = os.environ.get("AZDO_PAT", "")
WORKSPACE_DIR = Path(
    os.environ.get("WORKSPACE_DIR", str(Path.home() / "azdo-workspace"))
)
SBOM_OUT_DIR = Path(
    os.environ.get("SBOM_OUT_DIR", str(Path.home() / "azdo-scan" / "sbom"))
)
SECRETS_OUT_DIR = Path(
    os.environ.get("SECRETS_OUT_DIR", str(Path.home() / "azdo-scan" / "secrets"))
)


def parse_max_workers(raw_value):
    default_workers = max(1, os.cpu_count() or 4)
    if raw_value is None or str(raw_value).strip() == "":
        return default_workers
    value = str(raw_value).strip().lower()
    if value in ("auto", "cpu", "max", "default"):
        return default_workers
    try:
        parsed = int(value)
        return max(1, parsed)
    except ValueError:
        print(
            f"[WARN] Invalid MAX_WORKERS={raw_value!r}; falling back to {default_workers}",
            file=sys.stderr,
        )
        return default_workers


MAX_WORKERS = parse_max_workers(os.environ.get("MAX_WORKERS"))


def parse_positive_int_env(var_name, default_value):
    raw = os.environ.get(var_name)
    if raw is None or str(raw).strip() == "":
        return default_value
    try:
        return max(1, int(str(raw).strip()))
    except ValueError:
        print(
            f"[WARN] Invalid {var_name}={raw!r}; using default {default_value}",
            file=sys.stderr,
        )
        return default_value


# Concurrency control for network-heavy git ops
GIT_MAX_CONCURRENCY = parse_positive_int_env(
    "GIT_MAX_CONCURRENCY", min(MAX_WORKERS, 4)
)
GIT_NET_SEM = threading.Semaphore(GIT_MAX_CONCURRENCY)
GIT_CLONE_CONCURRENCY = parse_positive_int_env(
    "GIT_CLONE_CONCURRENCY", 1
)
GIT_CLONE_SEM = threading.Semaphore(GIT_CLONE_CONCURRENCY)

# Retry/backoff tuning
GIT_MAX_RETRIES = parse_positive_int_env("GIT_MAX_RETRIES", 3)
HTTP_MAX_RETRIES = parse_positive_int_env("HTTP_MAX_RETRIES", 4)
BACKOFF_BASE_MS = parse_positive_int_env("BACKOFF_BASE_MS", 300)
BACKOFF_MAX_MS = parse_positive_int_env("BACKOFF_MAX_MS", 5000)
START_STAGGER_MS = parse_positive_int_env("START_STAGGER_MS", 0)


def parse_bool_env(var_name, default_value):
    raw = os.environ.get(var_name)
    if raw is None:
        return default_value
    val = str(raw).strip().lower()
    return val in ("1", "true", "yes", "on")


# Quiet git console noise by default
GIT_QUIET = parse_bool_env("GIT_QUIET", True)
GIT_PARTIAL_CLONE = parse_bool_env("GIT_PARTIAL_CLONE", False)
DEBUG = parse_bool_env("DEBUG", False)
GIT_FALLBACK_HTTPS = parse_bool_env("GIT_FALLBACK_HTTPS", True)
UPDATE_EXISTING = parse_bool_env("UPDATE_EXISTING", True)
ONLY_UPDATE = parse_bool_env("ONLY_UPDATE", False)
GIT_FALLBACK_REMOTE_MODE = os.environ.get("GIT_FALLBACK_REMOTE_MODE", "url").strip().lower()
SKIP_IF_RESULTS_EXIST = parse_bool_env("SKIP_IF_RESULTS_EXIST", True)
ONLY_VERIFIED = os.environ.get("TRUFFLEHOG_ONLY_VERIFIED", "").lower() in (
    "1",
    "true",
    "yes",
)

# Configure SSH behavior for git to be more resilient on flaky networks
GIT_SSH_OPTS = os.environ.get(
    "GIT_SSH_OPTS",
    "-o ConnectTimeout=20 -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o PreferredAuthentications=publickey -o IPQoS=throughput",
)
# Allow selecting a specific SSH private key for AzDo
GIT_SSH_KEY = os.environ.get("GIT_SSH_KEY") or os.environ.get("AZDO_SSH_KEY")

# Set once for all git invocations (unless user already provided a custom command)
if "GIT_SSH_COMMAND" not in os.environ:
    if GIT_SSH_KEY:
        # Force using this identity and avoid trying other keys from the agent
        os.environ["GIT_SSH_COMMAND"] = (
            f"ssh {GIT_SSH_OPTS} -i {GIT_SSH_KEY} -o IdentitiesOnly=yes"
        )
    else:
        os.environ["GIT_SSH_COMMAND"] = f"ssh {GIT_SSH_OPTS}"
os.environ.setdefault("GIT_SSH_VARIANT", "ssh")

API_VER = "7.1-preview.1"
SESSION = requests.Session()


def fail(msg, code=1):
    print(f"\x1b[1;31m❌  {msg}\x1b[0m", file=sys.stderr)
    sys.exit(code)


def check_env():
    if not AZDO_ORG_URL or not AZDO_PROJECT or not AZDO_PAT:
        fail("AZDO_ORG_URL, AZDO_PROJECT, and AZDO_PAT must be set.")


# Pretty logging helpers
def _c(code: str) -> str:
    return f"\x1b[{code}m"


CLR = {
    "reset": _c("0"),
    "dim": _c("2"),
    "blue": _c("34"),
    "green": _c("32"),
    "yellow": _c("33"),
    "red": _c("31"),
    "magenta": _c("35"),
}


def log_info(msg: str):
    print(f"{CLR['blue']}ℹ️  {msg}{CLR['reset']}")


def log_ok(msg: str):
    print(f"{CLR['green']}✅  {msg}{CLR['reset']}")


def log_warn(msg: str):
    print(f"{CLR['yellow']}⚠️  {msg}{CLR['reset']}", file=sys.stderr)


def log_error(msg: str):
    print(f"{CLR['red']}❌  {msg}{CLR['reset']}", file=sys.stderr)


def log_skip(msg: str):
    print(f"{CLR['magenta']}⏭️  {msg}{CLR['reset']}")


def azdo_headers():
    # Azure DevOps REST: Basic auth with :PAT or pat:pat — both work; :PAT keeps username empty
    token = base64.b64encode(f":{AZDO_PAT}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
    }


def git_auth_header_value():
    # Basic auth header value for git http.extraHeader
    return f"Basic {base64.b64encode(f':{AZDO_PAT}'.encode()).decode()}"


def list_repos():
    url = f"{AZDO_ORG_URL}/{AZDO_PROJECT}/_apis/git/repositories?api-version={API_VER}"
    # Simple retry with backoff on 429/5xx
    attempt = 0
    while True:
        r = SESSION.get(url, headers=azdo_headers(), timeout=60)
        if r.status_code == 200:
            data = r.json()
            break
        attempt += 1
        if r.status_code in (429,) or 500 <= r.status_code < 600:
            if attempt > HTTP_MAX_RETRIES:
                fail(
                    f"Failed to list repositories after retries. HTTP {r.status_code}: {r.text[:300]}"
                )
            retry_after = r.headers.get("Retry-After")
            if retry_after:
                try:
                    sleep_sec = float(retry_after)
                except ValueError:
                    sleep_sec = 0
            else:
                jitter = random.uniform(0, 1)
                backoff_ms = min(
                    BACKOFF_MAX_MS,
                    int((2 ** (attempt - 1)) * BACKOFF_BASE_MS + jitter * BACKOFF_BASE_MS),
                )
                sleep_sec = backoff_ms / 1000.0
            log_warn(
                f"list_repos HTTP {r.status_code}; retrying in {sleep_sec:.2f}s (attempt {attempt}/{HTTP_MAX_RETRIES})"
            )
            time.sleep(sleep_sec)
            continue
        else:
            fail(f"Failed to list repositories. HTTP {r.status_code}: {r.text[:300]}")
    items = []
    for repo in data.get("value", []):
        name = repo.get("name")
        if not name:
            continue
        remote = repo.get("remoteUrl") or repo.get("webUrl")
        ssh = repo.get("sshUrl")
        disabled = bool(repo.get("isDisabled") or (str(repo.get("status") or "").lower() == "disabled"))
        if not (remote or ssh):
            continue
        items.append({
            "name": name,
            "remoteUrl": remote,
            "sshUrl": ssh,
            "disabled": disabled,
        })
    return items


def have(cmd):
    return shutil.which(cmd) is not None


def choose_sbom_tool():
    if have("cdxgen"):
        return "cdxgen"
    if have("syft"):
        return "syft"
    return None


def get_azdo_org_name(org_url):
    # Supports https://dev.azure.com/{org} and https://{org}.visualstudio.com
    try:
        # Normalize
        if not org_url:
            return ""
        # Drop scheme
        without_scheme = org_url.split("://", 1)[-1]
        host_and_path = without_scheme.split("/", 1)
        host = host_and_path[0]
        path = host_and_path[1] if len(host_and_path) > 1 else ""

        if host.endswith("visualstudio.com"):
            # {org}.visualstudio.com
            return host.split(".visualstudio.com", 1)[0]
        if host == "dev.azure.com":
            # dev.azure.com/{org}
            parts = [p for p in path.split("/") if p]
            return parts[0] if parts else ""
        # Fallback: if path contains org, use first path part
        parts = [p for p in path.split("/") if p]
        return parts[0] if parts else host.split(".")[0]
    except Exception:
        return ""


def build_ssh_remote_url(repo_name):
    org = get_azdo_org_name(AZDO_ORG_URL)
    # Azure DevOps SSH format: git@ssh.dev.azure.com:v3/{org}/{project}/{repo}
    return f"git@ssh.dev.azure.com:v3/{org}/{AZDO_PROJECT}/{repo_name}"


def build_https_remote_url(repo_name):
    org = get_azdo_org_name(AZDO_ORG_URL)
    # Azure DevOps HTTPS format: https://dev.azure.com/{org}/{project}/_git/{repo}
    return f"https://dev.azure.com/{org}/{AZDO_PROJECT}/_git/{repo_name}"


def run(cmd, cwd=None, stdout_path=None):
    # Stream to file if provided; otherwise inherit stdout
    stdout_f = open(stdout_path, "wb") if stdout_path else None
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            stdout=stdout_f or None,
            stderr=subprocess.STDOUT,
            check=False,
            text=False,
        ).returncode
    finally:
        if stdout_f:
            stdout_f.close()


def run_capture(cmd, cwd=None, timeout_s=60):
    try:
        p = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
            timeout=timeout_s,
        )
        return p.returncode, p.stdout or ""
    except Exception as e:
        return 1, str(e)


def run_with_retry(cmd, cwd=None, stdout_path=None, max_retries=None, context=None):
    attempts = 0
    max_r = GIT_MAX_RETRIES if max_retries is None else max_retries
    while True:
        temp_path = None
        effective_out = stdout_path
        # If we're quieting output to devnull, capture to a temp file so we can show a short error snippet on failure
        if effective_out == os.devnull and context:
            tf = tempfile.NamedTemporaryFile(delete=False)
            temp_path = tf.name
            tf.close()
            effective_out = temp_path

        if DEBUG and context:
            try:
                rendered = shlex.join([str(c) for c in cmd])
            except Exception:
                rendered = ' '.join([str(c) for c in cmd])
            log_info(f"exec: {context} → {rendered}")
        rc = run(cmd, cwd=cwd, stdout_path=effective_out)
        if rc == 0:
            if temp_path:
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            return rc
        attempts += 1
        if attempts > max_r:
            # Final failure; if we captured output, show a short tail to aid debugging
            snippet = None
            if temp_path:
                try:
                    with open(temp_path, "rb") as f:
                        data = f.read()
                        snippet = data[-500:].decode(errors="ignore").strip()
                except Exception:
                    snippet = None
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            if context:
                if snippet:
                    log_warn(f"{context} failed rc={rc}. Last output:\n{snippet}")
                else:
                    log_warn(f"{context} failed rc={rc}")
            return rc
        jitter = random.uniform(0, 1)
        backoff_ms = min(
            BACKOFF_MAX_MS,
            int((2 ** (attempts - 1)) * BACKOFF_BASE_MS + jitter * BACKOFF_BASE_MS),
        )
        sleep_sec = backoff_ms / 1000.0
        prefix = f"{context}: " if context else ""
        # If debugging, show a short tail from the temp output on each retry
        if DEBUG and temp_path:
            try:
                with open(temp_path, "rb") as f:
                    data = f.read()
                    snippet_retry = data[-240:].decode(errors="ignore").strip()
                log_warn(f"{prefix}rc={rc}; tail:\n{snippet_retry}")
            except Exception:
                pass
        log_warn(f"{prefix}rc={rc}; retrying in {sleep_sec:.2f}s (attempt {attempts}/{max_r})")
        time.sleep(sleep_sec)


def safe_basename(project, repo):
    # Normalize basename for files
    return f"{project}_{repo}".replace("/", "_").replace(" ", "_")


def ensure_dirs():
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    SBOM_OUT_DIR.mkdir(parents=True, exist_ok=True)
    SECRETS_OUT_DIR.mkdir(parents=True, exist_ok=True)

def git_clone_or_fetch(ssh_url, https_url, target_dir):
    if target_dir.exists() and (target_dir / ".git").exists():
        # Ensure remote origin uses expected SSH URL (update stale HTTPS remotes)
        set_remote_cmd = [
            "git",
            "-C",
            str(target_dir),
            "remote",
            "set-url",
            "origin",
            ssh_url,
        ]
        rc_set = run(set_remote_cmd, stdout_path=(os.devnull if GIT_QUIET else None))
        if rc_set != 0:
            return False, f"git remote set-url failed rc={rc_set}"
        # Verify the remote was set correctly
        rc_verify, current_remote = run_capture(
            ["git", "-C", str(target_dir), "remote", "get-url", "origin"], timeout_s=10
        )
        if rc_verify != 0 or current_remote.strip() != ssh_url:
            log_warn(f"Remote URL mismatch: expected {ssh_url}, got {current_remote.strip()}")
        # Fetch / prune to update
        cmd = [
            "git",
            "-C",
            str(target_dir),
            "fetch",
            "--all",
            "--prune",
        ]
        if GIT_QUIET:
            cmd.append("--quiet")
        with GIT_NET_SEM:
            rc = run_with_retry(
                cmd,
                stdout_path=(os.devnull if GIT_QUIET else None),
                context=f"fetch {target_dir.name}",
            )
        if rc != 0 and GIT_FALLBACK_HTTPS:
            if not https_url:
                log_warn(f"HTTPS fallback not possible for {target_dir.name}: no https URL")
                return False, f"git fetch failed rc={rc}"
            if not AZDO_PAT:
                log_warn(f"HTTPS fallback requested for {target_dir.name} but AZDO_PAT is empty; skipping fallback")
            else:
                log_info(f"Falling back to HTTPS fetch for {target_dir.name}")
            # Try HTTPS fetch with PAT header
            header = f"AUTHORIZATION: {git_auth_header_value()}"
            if GIT_FALLBACK_REMOTE_MODE == "swap":
                # Temporarily switch origin to https
                run([
                    "git","-C",str(target_dir),"remote","set-url","origin",https_url
                ], stdout_path=(os.devnull if GIT_QUIET else None))
                cmd_https = [
                    "git","-c",f"http.extraHeader={header}","-C",str(target_dir),
                    "fetch","--all","--prune",
                ]
            else:
                # Do not touch origin; fetch from URL into origin/* refs via refspec
                cmd_https = [
                    "git","-c",f"http.extraHeader={header}","-C",str(target_dir),
                    "fetch",https_url,"+refs/heads/*:refs/remotes/origin/*","--prune",
                ]
            if GIT_QUIET:
                cmd_https.append("--quiet")
            with GIT_NET_SEM:
                rc = run_with_retry(
                    cmd_https,
                    stdout_path=(os.devnull if GIT_QUIET else None),
                    context=f"fetch-https {target_dir.name}",
                )
            if rc != 0:
                return False, f"git fetch failed rc={rc}"
        elif rc != 0:
            return False, f"git fetch failed rc={rc}"
        # Reset local default branch to remote HEAD for a clean scan of HEAD
        reset_cmd = [
            "git",
            "-C",
            str(target_dir),
            "reset",
            "--hard",
            "origin/HEAD",
        ]
        if GIT_QUIET:
            reset_cmd.append("--quiet")
        run(reset_cmd, stdout_path=(os.devnull if GIT_QUIET else None))
        return True, "updated"
    else:
        cmd = [
            "git",
            "clone",
            "--no-tags",
            "--origin",
            "origin",
            ssh_url,
            str(target_dir),
        ]
        if GIT_PARTIAL_CLONE:
            # Partial clone reduces transferred data but may hide blobs from scanners
            cmd.insert(3, "--filter=blob:none")
        if GIT_QUIET:
            cmd.insert(2, "--quiet")
        with GIT_CLONE_SEM:
            rc = run_with_retry(
                cmd,
                stdout_path=(os.devnull if GIT_QUIET else None),
                context=f"clone {target_dir.name}",
            )
        if rc != 0 and GIT_FALLBACK_HTTPS:
            if not https_url:
                log_warn(f"HTTPS fallback not possible for {target_dir.name}: no https URL")
                return False, f"git clone failed rc={rc}"
            if not AZDO_PAT:
                log_warn(f"HTTPS fallback requested for {target_dir.name} but AZDO_PAT is empty; skipping fallback")
                return False, f"git clone failed rc={rc}"
            log_info(f"Falling back to HTTPS clone for {target_dir.name}")
            # Try HTTPS clone with PAT header
            header = f"AUTHORIZATION: {git_auth_header_value()}"
            cmd_https = [
                "git",
                "-c",
                f"http.extraHeader={header}",
                "clone",
                "--no-tags",
                "--origin",
                "origin",
                https_url,
                str(target_dir),
            ]
            if GIT_PARTIAL_CLONE:
                cmd_https.insert(5, "--filter=blob:none")
            if GIT_QUIET:
                cmd_https.insert(2, "--quiet")
            with GIT_CLONE_SEM:
                rc = run_with_retry(
                    cmd_https,
                    stdout_path=(os.devnull if GIT_QUIET else None),
                    context=f"clone-https {target_dir.name}",
                )
            if rc != 0:
                return False, f"git clone failed rc={rc}"
        elif rc != 0:
            return False, f"git clone failed rc={rc}"
        return True, "cloned"


def classify_repo_access(remote_url):
    # Quick probe to distinguish missing/renamed vs permission/SSH issues
    rc, out = run_capture(["git", "ls-remote", "--heads", remote_url], timeout_s=30)
    out_l = (out or "").lower()
    if rc == 0:
        return "ok", None
    # Detect timeouts first (generic git footer includes 'access rights' even on timeouts)
    if (
        "operation timed out" in out_l
        or "connection timed out" in out_l
        or "timed out" in out_l
        or "connect to host" in out_l and "port 22" in out_l and "timed out" in out_l
        or "connection reset" in out_l
    ):
        return "timeout", out
    # Missing or renamed
    if "tf401019" in out_l or "repository not found" in out_l or "not found" in out_l:
        return "not-found-or-renamed", out
    # Explicit permission errors (avoid matching the generic hint line alone)
    if "permission denied (publickey)" in out_l or "permission denied (keyboard-interactive)" in out_l or "auth fail" in out_l:
        return "no-permission", out
    return "unknown", out


def generate_sbom(sbom_tool, repo_dir, out_file):
    if sbom_tool == "cdxgen":
        # cdxgen auto-detects ecosystems; -r for recursive; use JSON CycloneDX by default
        cmd = ["cdxgen", "-r", "-o", str(out_file), str(repo_dir)]
    elif sbom_tool == "syft":
        # syft to CycloneDX JSON
        cmd = ["syft", str(repo_dir), "-o", "cyclonedx-json"]
        return run(cmd, stdout_path=str(out_file))
    else:
        return 127  # tool missing
    return run(cmd)


def run_trufflehog(repo_dir, out_file):
    # Prefer full history scan; JSONL output; run in repo dir
    base_cmd = ["trufflehog", "git", ".", "--json"]
    if ONLY_VERIFIED:
        base_cmd.append("--only-verified")
    rc = run(base_cmd, cwd=str(repo_dir), stdout_path=str(out_file))
    if rc == 0:
        return rc
    # Retry disabling self-update/network touches
    retry_cmd = base_cmd + ["--no-update"]
    rc2 = run(retry_cmd, cwd=str(repo_dir), stdout_path=str(out_file))
    if rc2 == 0:
        return rc2
    # Last fallback: filesystem scan (less complete than git history)
    fs_cmd = ["trufflehog", "filesystem", ".", "--json"]
    if ONLY_VERIFIED:
        fs_cmd.append("--only-verified")
    return run(fs_cmd, cwd=str(repo_dir), stdout_path=str(out_file))


def process_repo(project, repo_name, ssh_url, https_url, sbom_tool):
    result = {
        "repo": repo_name,
        "clone": None,
        "clone_class": None,
        "sbom": None,
        "secrets": None,
        "errors": [],
    }
    repo_dir = WORKSPACE_DIR / repo_name
    base = safe_basename(project, repo_name)
    sbom_file = SBOM_OUT_DIR / f"{base}.cdx.json"
    secrets_file = SECRETS_OUT_DIR / f"{base}.trufflehog.jsonl"

    # Optional start jitter to avoid burst traffic
    if START_STAGGER_MS > 0:
        time.sleep(random.uniform(0, START_STAGGER_MS) / 1000.0)
    # Informative, low-noise status line
    # If both outputs exist, optionally skip the repo entirely
    if SKIP_IF_RESULTS_EXIST and sbom_file.exists() and secrets_file.exists():
        log_skip(f"{repo_name} results already exist → skip")
        return {
            "repo": repo_name,
            "clone": "results-exist-skip",
            "clone_class": "results-exist-skip",
            "sbom": f"exists:{sbom_file}",
            "secrets": f"exists:{secrets_file}",
            "errors": [],
        }
    if (repo_dir / ".git").exists():
        if not UPDATE_EXISTING:
            log_skip(f"{repo_name} exists → skip update")
            result["clone"] = "exists-skipped"
            result["clone_class"] = "exists-skipped"
            return result
        log_info(f"Updating {repo_name}")
    else:
        if ONLY_UPDATE:
            log_skip(f"{repo_name} missing → skip clone (ONLY_UPDATE)")
            result["clone"] = "missing-skipped"
            result["clone_class"] = "missing-skipped"
            return result
        log_info(f"Cloning {repo_name}")
    ok, status = git_clone_or_fetch(ssh_url, https_url, repo_dir)
    if ok:
        log_ok(f"{repo_name} {status}")
        result["clone_class"] = "ok"
    else:
        # Classify error to improve summary and optionally skip
        cls, details = classify_repo_access(ssh_url)
        if cls in ("not-found-or-renamed", "no-permission"):
            log_skip(f"{repo_name} {cls}")
            result["clone"] = cls
            result["clone_class"] = cls
            result["errors"].append(cls)
            return result
        log_error(f"{repo_name} {status}")
        result["clone_class"] = cls or "error"
    result["clone"] = status
    if not ok:
        result["errors"].append(f"clone/fetch: {status}")
        return result

    # SBOM
    if sbom_file.exists():
        result["sbom"] = f"exists:{sbom_file}"
        log_skip(f"SBOM {repo_name} exists → skip")
    else:
        log_info(f"SBOM {repo_name} with {sbom_tool}")
        rc = generate_sbom(sbom_tool, repo_dir, sbom_file)
        result["sbom"] = f"written:{sbom_file}" if rc == 0 else f"failed rc={rc}"
        if rc != 0:
            result["errors"].append(f"sbom rc={rc}")
            log_error(f"SBOM {repo_name} rc={rc}")
        else:
            log_ok(f"SBOM {repo_name} -> {sbom_file}")

    # Secrets
    if secrets_file.exists():
        result["secrets"] = f"exists:{secrets_file}"
        log_skip(f"TruffleHog {repo_name} exists → skip")
    else:
        log_info(f"TruffleHog {repo_name}")
        rc2 = run_trufflehog(repo_dir, secrets_file)
        result["secrets"] = f"written:{secrets_file}" if rc2 == 0 else f"failed rc={rc2}"
        if rc2 != 0:
            result["errors"].append(f"trufflehog rc={rc2}")
            log_error(f"TruffleHog {repo_name} rc={rc2}")
        else:
            log_ok(f"TruffleHog {repo_name} -> {secrets_file}")

    return result


def main():
    check_env()
    ensure_dirs()
    repos = list_repos()
    if not repos:
        fail("No repositories found for the specified project.")

    sbom_tool = choose_sbom_tool()
    if not sbom_tool:
        fail(
            "No SBOM tool found. Install cdxgen (preferred) or syft and ensure it is on PATH."
        )

    log_info(
        f"Project: {AZDO_PROJECT}  Repos: {len(repos)}  Workers: {MAX_WORKERS}  SBOM: {sbom_tool}"
    )
    results = []
    # Skip disabled repositories early and prepare actionable plan
    active_repos = []
    for r in repos:
        if r.get("disabled"):
            log_skip(f"{r['name']} disabled")
            results.append({
                "repo": r["name"],
                "clone": "disabled",
                "sbom": None,
                "secrets": None,
                "errors": ["disabled"],
            })
        else:
            active_repos.append(r)

    # Build plan: decide clone vs update vs skip (exists/missing) and show counts
    to_run = []
    planned_clone = planned_update = planned_skip = 0
    for r in active_repos:
        name = r["name"]
        ssh_u = (r.get("sshUrl") or build_ssh_remote_url(name))
        https_u = (r.get("remoteUrl") or build_https_remote_url(name))
        repo_dir = WORKSPACE_DIR / name
        if (repo_dir / ".git").exists():
            if not UPDATE_EXISTING:
                planned_skip += 1
                results.append({
                    "repo": name,
                    "clone": "exists-skipped",
                    "sbom": None,
                    "secrets": None,
                    "errors": ["exists-skipped"],
                })
                continue
            planned_update += 1
        else:
            if os.environ.get("ONLY_UPDATE", "").lower() in ("1", "true", "yes", "on"):
                planned_skip += 1
                results.append({
                    "repo": name,
                    "clone": "missing-skipped",
                    "sbom": None,
                    "secrets": None,
                    "errors": ["missing-skipped"],
                })
                continue
            planned_clone += 1
        to_run.append((name, ssh_u, https_u))

    total_tasks = len(to_run)
    log_info(
        f"Plan: clone {planned_clone}, update {planned_update}, skip {planned_skip} → total {total_tasks}"
    )

    # Progress tracking
    done = 0
    failed = 0
    prog_lock = threading.Lock()

    def _on_done(fut):
        nonlocal done, failed
        try:
            res = fut.result()
        except Exception:
            res = {"errors": ["exception"]}
        with prog_lock:
            done += 1
            if res and res.get("errors"):
                failed += 1
            log_info(f"Progress: {done}/{total_tasks} done, failures {failed}")

    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = []
        for name, ssh_u, https_u in to_run:
            fut = pool.submit(
                process_repo,
                AZDO_PROJECT,
                name,
                ssh_u,
                https_u,
                sbom_tool,
            )
            fut.add_done_callback(_on_done)
            futs.append(fut)
        for f in cf.as_completed(futs):
            results.append(f.result())

    # Re-process transient failures (timeouts/unknown) once at the end
    retry_candidates = [
        r for r in results if r.get("clone_class") in ("timeout", "unknown")
    ]
    if retry_candidates:
        log_info(
            f"Re-processing {len(retry_candidates)} transient failures after initial pass"
        )
        name_to_repo = {r["name"]: r for r in active_repos}
        with cf.ThreadPoolExecutor(max_workers=min(2, MAX_WORKERS)) as pool:
            futs2 = []
            for rr in retry_candidates:
                src = name_to_repo.get(rr["repo"])
                if not src:
                    continue
                futs2.append(
                    pool.submit(
                        process_repo,
                        AZDO_PROJECT,
                        rr["repo"],
                        (src.get("sshUrl") or build_ssh_remote_url(rr["repo"])) ,
                        (src.get("remoteUrl") or build_https_remote_url(rr["repo"])),
                        sbom_tool,
                    )
                )
            for f in cf.as_completed(futs2):
                results.append(f.result())

    # Minimal structured summary
    summary = {
        "project": AZDO_PROJECT,
        "workspace": str(WORKSPACE_DIR),
        "sbom_output_dir": str(SBOM_OUT_DIR),
        "secrets_output_dir": str(SECRETS_OUT_DIR),
        "count_repos": len(repos),
        "sbom_tool": sbom_tool,
        "only_verified": ONLY_VERIFIED,
        "results": results,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
