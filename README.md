## Azure DevOps Clone & Scan

Script to list repositories from an Azure DevOps project, clone/update them over SSH, generate an SBOM, and scan for secrets. Includes throttling controls, pretty colored logs, retries with backoff, SSH key selection, repo status handling (disabled/renamed/no-permission), and a final retry pass for transient failures.

Made by Omnivya.

### Requirements
- Python 3.13+
- `uv` package manager (recommended)
- Tools (optional but recommended):
  - `cdxgen` (preferred) or `syft` for SBOM generation
  - `trufflehog` for secret scanning
- SSH key configured on Azure DevOps (`git@ssh.dev.azure.com`)

### Installation
```bash
uv sync
```

### Environment Variables
Put these in a `.env` file or set them in your environment.

- AZDO_ORG_URL: Azure DevOps org URL. Examples:
  - `https://dev.azure.com/<org>`
  - `https://<org>.visualstudio.com`
- AZDO_PROJECT: Azure DevOps project name
- AZDO_PAT: Azure DevOps Personal Access Token (used only for REST listing)
- WORKSPACE_DIR: Directory where repos are cloned (default: `~/azdo-workspace`)
- SBOM_OUT_DIR: Directory for SBOM outputs (default: `~/azdo-scan/sbom`)
- SECRETS_OUT_DIR: Directory for TruffleHog outputs (default: `~/azdo-scan/secrets`)
- MAX_WORKERS: Thread count for per-repo processing
  - Accepts integer or keywords: `auto`, `cpu`, `max`, `default`

Throttling and noise control:
- GIT_MAX_CONCURRENCY: Max concurrent networked git ops (default: `min(MAX_WORKERS, 4)`)
- GIT_CLONE_CONCURRENCY: Max concurrent clones (default: `1`)
- GIT_MAX_RETRIES: Retries for git clone/fetch (default: `3`)
- HTTP_MAX_RETRIES: Retries for REST listing (default: `4`)
- BACKOFF_BASE_MS: Backoff base in ms (default: `300`)
- BACKOFF_MAX_MS: Backoff max in ms (default: `5000`)
- START_STAGGER_MS: Random startup jitter per repo in ms (default: `0`)
- GIT_QUIET: Suppress git stdout (`true`/`false`, default: `true`)
- GIT_PARTIAL_CLONE: Use `--filter=blob:none` on clone (default: `false`)
- NO_COLOR: Disable ANSI colors in logs (any value → disables)

SSH:
- GIT_SSH_KEY or AZDO_SSH_KEY: Path to private key to use (forces `IdentitiesOnly=yes`)
- GIT_SSH_OPTS: Extra ssh options (default includes `ConnectTimeout=20`, keepalives, `PreferredAuthentications=publickey`, `IPQoS=throughput`)

### SSH Configuration
Ensure your SSH key is set up for Azure DevOps:
```bash
ssh -T git@ssh.dev.azure.com
```
Repository URLs are constructed as: `git@ssh.dev.azure.com:v3/{org}/{project}/{repo}`.

Note: The script prefers `sshUrl` returned by the Azure DevOps REST API when present, and falls back to the constructed URL only if missing. Existing clones have their `origin` URL updated automatically.

### Usage
With `.env`:
```bash
uv run --env-file .env ./azdo_clone_and_scan.py
```

Override or add flags inline:
```bash
uv run --env-file .env GIT_MAX_CONCURRENCY=3 START_STAGGER_MS=500 ./azdo_clone_and_scan.py
```

Note on TruffleHog: partial clones can yield empty results because blobs are not fetched. The default here disables partial clone. If you need lower bandwidth, enable `GIT_PARTIAL_CLONE=true` but be aware scans may be incomplete unless you fetch full history/blobs.

Extra options for TruffleHog:
- TRUFFLEHOG_ONLY_VERIFIED: `true|false` (default follows your env)
- TRUFFLEHOG_ARGS: additional flags appended to the command, e.g. `--branch main` or `--since-commit <sha>`

Without code changes you can also point to a custom env file:
```bash
uv run --env-file .env ./azdo_clone_and_scan.py
```

### What it does
For each repository in the Azure DevOps project:
1. Skips disabled repositories (from REST API `isDisabled`/`status`)
2. Clone over SSH if missing (using API `sshUrl` if available), or fetch/prune and hard reset to `origin/HEAD` if present
2. Generate an SBOM (prefers `cdxgen`, falls back to `syft`)
3. Run `trufflehog` secret scan
4. Classifies failures: `disabled`, `not-found-or-renamed`, `no-permission`, `timeout`, `unknown`
5. Performs a final limited retry pass for transient classes (`timeout`, `unknown`)
6. Appends results to a final JSON summary printed on stdout

Status lines are printed per repo with colors/emojis:
- Starting: `ℹ️ Cloning <repo>` or `ℹ️ Updating <repo>`
- SBOM/Secrets: `ℹ️ SBOM <repo> with <tool>` and `ℹ️ TruffleHog <repo>`
- Completion: `✅ <repo> cloned/updated`, `✅ SBOM ...`, `✅ TruffleHog ...` or `❌ ...`
- Skips: `⏭️ <repo> disabled|not-found-or-renamed|no-permission`

### Output
- SBOM: `${SBOM_OUT_DIR}/{project}_{repo}.cdx.json`
- Secrets: `${SECRETS_OUT_DIR}/{project}_{repo}.trufflehog.jsonl`
- Final summary: JSON to stdout

### Tuning concurrency
- `MAX_WORKERS` controls total threads
- `GIT_MAX_CONCURRENCY` caps simultaneous git fetch network ops
- `GIT_CLONE_CONCURRENCY` caps simultaneous clones
- `START_STAGGER_MS` reduces start bursts
- Retries/backoff (with jitter) applied to git and REST calls

### Troubleshooting
- `ModuleNotFoundError: requests` → run `uv sync`
- SSH permission denied → add your key to Azure DevOps and ensure ssh-agent is loaded (`ssh-add -l`)
- Rate limiting (429) → lower `GIT_MAX_CONCURRENCY`, increase `START_STAGGER_MS`, or keep defaults to let backoff handle it
- Timeouts to `ssh.dev.azure.com:22` → reduce clone concurrency, raise `ConnectTimeout` in `GIT_SSH_OPTS`, or re-run at a quieter time; the script will auto-retry and re-process transient failures at the end

### Two-phase mode (optional)
Currently, each repo is scanned right after its clone/update. If you want a two-phase mode (clone all, then scan), open an issue or adjust the flow; the code is structured to make this change straightforward.

## Dependency-Track bulk uploader (`dt_bulk_upload_sbom.py`)

Uploads CycloneDX SBOMs to Dependency-Track.

Highlights:
- Validates project existence via `/api/v1/project/lookup` and creates it when `DT_AUTOCREATE=true`
- Optionally waits for processing via token polling

Env:
- `DT_URL`, `DT_API_KEY` (required)
- `SBOM_DIR` (default `~/azdo-scan/sbom`)
- `DT_DEFAULT_VERSION` (default `HEAD`)
- `DT_AUTOCREATE` (default `true`)
- `WAIT_FOR_PROCESSING` (default `false`)
- `MAX_WORKERS` (same parsing as above)

Run:
```bash
uv run --env-file .env ./dt_bulk_upload_sbom.py
```


