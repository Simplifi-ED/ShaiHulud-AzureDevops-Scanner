#!/usr/bin/env python3
import concurrent.futures as cf
import json
import os
import re
import time
from pathlib import Path
from typing import Tuple, Optional

import requests
import sys

DT_URL = os.environ.get("DT_URL", "").rstrip("/")
DT_API_KEY = os.environ.get("DT_API_KEY", "")
SBOM_DIR = Path(os.environ.get("SBOM_DIR", str(Path.home() / "azdo-scan" / "sbom")))
DT_DEFAULT_VERSION = os.environ.get("DT_DEFAULT_VERSION", "HEAD")
DT_AUTOCREATE = os.environ.get("DT_AUTOCREATE", "true").lower() in ("1", "true", "yes")
WAIT_FOR_PROCESSING = os.environ.get("WAIT_FOR_PROCESSING", "false").lower() in (
    "1",
    "true",
    "yes",
)

API_BOM = f"{DT_URL}/api/v1/bom"
API_BOM_TOKEN = f"{DT_URL}/api/v1/bom/token"
API_PROJECT = f"{DT_URL}/api/v1/project"

HDRS = {"X-Api-Key": DT_API_KEY}


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


def must_env():
    if not DT_URL or not DT_API_KEY:
        raise SystemExit("DT_URL and DT_API_KEY must be set")


def derive_project(sbom_path: Path) -> Tuple[str, str]:
    """
    Derive projectName and projectVersion.
    Priority: CycloneDX metadata.component.{name, version} if present (JSON only),
    else filename stem as name and DT_DEFAULT_VERSION as version.
    """
    name = sbom_path.stem
    version = DT_DEFAULT_VERSION

    if sbom_path.suffix.lower() == ".json":
        try:
            data = json.loads(sbom_path.read_text(encoding="utf-8"))
            comp = (data.get("metadata") or {}).get("component") or {}
            n = comp.get("name")
            v = comp.get("version")
            if isinstance(n, str) and n.strip():
                name = n.strip()
            if isinstance(v, str) and v.strip():
                version = v.strip()
        except Exception:
            pass  # fall back to filename

    # normalize to something DT-friendly
    name = re.sub(r"[^A-Za-z0-9_.:/+ -]", "_", name).strip()
    version = re.sub(r"[^A-Za-z0-9_.:/+ -]", "_", version).strip() or DT_DEFAULT_VERSION
    return name, version


def find_project_id(name: str, version: str) -> Optional[str]:
    """Return project UUID if exists, else None."""
    # Search by name/version (Dependency-Track supports query params)
    try:
        r = requests.get(
            f"{API_PROJECT}/lookup",
            headers=HDRS,
            params={"name": name, "version": version},
            timeout=30,
        )
        if r.status_code == 200:
            data = r.json()
            # API returns a single project or 404; some deployments return list
            if isinstance(data, dict) and data.get("uuid"):
                return data.get("uuid")
            if isinstance(data, list) and data:
                item = data[0]
                if isinstance(item, dict) and item.get("uuid"):
                    return item.get("uuid")
        elif r.status_code == 404:
            return None
        else:
            print(
                f"[WARN] project lookup HTTP {r.status_code}: {r.text[:200]}",
                file=sys.stderr,
            )
    except Exception as e:
        print(f"[WARN] project lookup error: {e}", file=sys.stderr)
    return None


def ensure_project(name: str, version: str) -> Optional[str]:
    """Return project UUID, creating it if permitted and missing."""
    pid = find_project_id(name, version)
    if pid:
        return pid
    if not DT_AUTOCREATE:
        return None
    try:
        r = requests.put(
            API_PROJECT,
            headers={**HDRS, "Content-Type": "application/json"},
            data=json.dumps({"name": name, "version": version}),
            timeout=60,
        )
        if r.status_code in (200, 201):
            data = r.json()
            return data.get("uuid")
        print(
            f"[WARN] project create HTTP {r.status_code}: {r.text[:200]}",
            file=sys.stderr,
        )
    except Exception as e:
        print(f"[WARN] project create error: {e}", file=sys.stderr)
    return None


def post_bom_multipart(
    sbom_path: Path, project_name: str, project_version: str
) -> Tuple[bool, Optional[str], str]:
    """
    Upload via multipart/form-data. Returns (ok, token, message)
    """
    files = {"bom": (sbom_path.name, sbom_path.open("rb"), "application/octet-stream")}
    data = {"projectName": project_name, "projectVersion": project_version}
    if DT_AUTOCREATE:
        data["autoCreate"] = "true"

    r = requests.post(API_BOM, headers=HDRS, files=files, data=data, timeout=120)
    if r.status_code not in (200, 201):
        return False, None, f"HTTP {r.status_code}: {r.text[:300]}"
    try:
        token = r.json().get("token")
    except Exception:
        token = None
    return True, token, "accepted"


def poll_token(token: str, timeout_s: int = 600, base_sleep: float = 1.0) -> bool:
    """
    Poll /api/v1/bom/token/{token} until processing completes or timeout.
    Endpoint historically returned either a boolean or a JSON with 'processing' flag.
    """
    if not token:
        return True
    deadline = time.time() + timeout_s
    attempt = 0
    while time.time() < deadline:
        r = requests.get(f"{API_BOM_TOKEN}/{token}", headers=HDRS, timeout=30)
        if r.status_code == 200:
            processing = None
            ct = (r.headers.get("Content-Type") or "").lower()
            if "application/json" in ct:
                try:
                    j = r.json()
                    processing = j.get("processing")
                    if processing is None and isinstance(
                        j, bool
                    ):  # some deployments return bare bool JSON
                        processing = j
                except Exception:
                    pass
            if processing is None:
                txt = r.text.strip().lower()
                if txt in ("true", "false"):
                    processing = txt == "true"
            if processing is False:
                return True
        # backoff
        attempt += 1
        time.sleep(min(10.0, base_sleep * (2 ** min(attempt, 6))))
    return False


def discover_sboms(root: Path):
    exts = {".json", ".xml"}
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            yield p


def handle_one(sbom_path: Path) -> dict:
    name, version = derive_project(sbom_path)
    pid = ensure_project(name, version)
    if not pid:
        status = {
            "sbom": str(sbom_path),
            "projectName": name,
            "projectVersion": version,
            "accepted": False,
            "message": "project missing and autoCreate disabled",
            "token": None,
            "processed": None,
        }
        return status
    ok, token, msg = post_bom_multipart(sbom_path, name, version)
    status = {
        "sbom": str(sbom_path),
        "projectName": name,
        "projectVersion": version,
        "projectUuid": pid,
        "accepted": ok,
        "message": msg,
        "token": token,
        "processed": None,
    }
    if not ok:
        return status
    if WAIT_FOR_PROCESSING:
        status["processed"] = poll_token(token)
    return status


def main():
    must_env()
    if not SBOM_DIR.exists():
        raise SystemExit(f"SBOM_DIR not found: {SBOM_DIR}")
    items = list(discover_sboms(SBOM_DIR))
    if not items:
        raise SystemExit(f"No SBOMs found under {SBOM_DIR}")

    results = []
    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for res in pool.map(handle_one, items):
            print(json.dumps(res, ensure_ascii=False))
            results.append(res)

    # exit non-zero if any upload failed
    failures = [r for r in results if not r.get("accepted")]
    if failures:
        raise SystemExit(f"{len(failures)} upload(s) failed")


if __name__ == "__main__":
    main()
