# Azure DevOps Supply Chain Scanner

**Audit Azure DevOps repositories at scale: inventory codebases, generate CycloneDX SBOMs, scan for exposed secrets with TruffleHog, and push evidence into Dependency-Track for policy evaluation.**

**FR :** toolkit d'audit de supply chain logicielle pour Azure DevOps : inventaire des dépôts, SBOM CycloneDX, détection de secrets, Dependency-Track et politiques de composants à risque.

<p align="center">
  <a href="https://www.omnivya.fr/expertises/software-supply-chain-security/?utm_source=github&utm_medium=repository&utm_campaign=azure-devops-supply-chain-scanner&utm_content=readme">Software supply-chain security</a> ·
  <a href="https://www.omnivya.fr/fr/expertises/software-supply-chain-security/?utm_source=github&utm_medium=repository&utm_campaign=azure-devops-supply-chain-scanner&utm_content=readme-fr">FR</a> ·
  <a href="https://www.omnivya.fr/work/?utm_source=github&utm_medium=repository&utm_campaign=azure-devops-supply-chain-scanner&utm_content=public-work">Omnivya public work</a>
</p>

This toolkit is designed for repeatable assessment across **tens or hundreds of Azure DevOps repositories**, where repository inventory, dependency evidence, secret findings and policy results need to be collected consistently rather than assembled from ad-hoc commands.

> The current repository name references the original “Shai-Hulud” package-compromise investigation. The project scope is broader; the intended long-term name is **azure-devops-supply-chain-scanner**.

## What it collects

- Azure DevOps repository inventory and repeatable clone/update state.
- CycloneDX SBOMs via `cdxgen` with `syft` fallback.
- TruffleHog secret-scan evidence.
- Dependency-Track uploads, project creation, policy checks and reanalysis.
- Explicit failure/retry state so incomplete evidence is visible.

## Why this exists

A supply-chain review becomes difficult very quickly when an Azure DevOps project contains tens or hundreds of repositories. The important questions are not only "does this repository contain a vulnerable dependency?" but also:

- which repositories actually exist and are accessible;
- which dependencies are present across the estate;
- which source trees expose credentials or secrets;
- which scans failed or were incomplete;
- which components violate an explicit policy;
- how to refresh the evidence without manually processing every repository again.

This project automates that collection pipeline so the output can be reviewed as evidence rather than as a pile of ad-hoc commands.

## Audit pipeline

```text
Azure DevOps project
        |
        v
List repositories through REST
        |
        v
Clone / update repositories
        |
        +----------------------+
        |                      |
        v                      v
CycloneDX SBOM             TruffleHog
(cdxgen / syft)           secret scan
        |                      |
        +----------+-----------+
                   |
                   v
          Local audit outputs
                   |
                   v
          Dependency-Track
                   |
                   v
        Policy evaluation / reanalysis
```

## Capabilities

### Repository inventory and acquisition

`azdo_clone_and_scan.py`:

- lists repositories from an Azure DevOps project through the REST API;
- prefers Azure DevOps SSH clone URLs;
- clones missing repositories and updates existing clones;
- skips disabled repositories;
- classifies common failures such as missing repositories, permissions and timeouts;
- retries transient failures with bounded backoff;
- supports concurrency controls to avoid overwhelming Azure DevOps or the local machine.

### SBOM generation

For each repository, the scanner generates a CycloneDX SBOM using:

1. `cdxgen`, when available;
2. `syft`, as a fallback.

Outputs are written as one SBOM per repository.

### Secret scanning

The same workflow runs TruffleHog against repository content and stores JSONL findings per repository.

> Partial Git clones can reduce scan completeness because the required blobs may not be available. Full-history/content acquisition is therefore the safer default when the goal is audit evidence.

### Dependency-Track integration

The repository includes scripts to:

- bulk-upload generated SBOMs;
- optionally create missing Dependency-Track projects;
- wait for BOM processing;
- create a global package blocklist policy;
- add PURL-based conditions to an existing policy;
- trigger project reanalysis and metrics refresh.

## Requirements

- Python 3.13+
- [`uv`](https://docs.astral.sh/uv/) recommended for dependency management
- Azure DevOps access
- SSH key configured for Azure DevOps repository access
- Azure DevOps PAT for REST repository discovery

Optional but recommended scanning tools:

- `cdxgen`
- `syft`
- `trufflehog`

Dependency-Track is only required for the upload and policy stages.

## Installation

```bash
uv sync
```

## Quick start

### 1. Configure Azure DevOps access

Create a `.env` file or export equivalent variables:

```text
AZDO_ORG_URL=https://dev.azure.com/<org>
AZDO_PROJECT=<project>
AZDO_PAT=<pat>
```

Useful optional paths and concurrency settings include:

```text
WORKSPACE_DIR=~/azdo-workspace
SBOM_OUT_DIR=~/azdo-scan/sbom
SECRETS_OUT_DIR=~/azdo-scan/secrets
MAX_WORKERS=auto
GIT_MAX_CONCURRENCY=4
GIT_CLONE_CONCURRENCY=1
```

Configure SSH access and verify it independently:

```bash
ssh -T git@ssh.dev.azure.com
```

### 2. Clone/update and scan repositories

```bash
uv run --env-file .env ./azdo_clone_and_scan.py
```

The workflow produces:

```text
${SBOM_OUT_DIR}/{project}_{repo}.cdx.json
${SECRETS_OUT_DIR}/{project}_{repo}.trufflehog.jsonl
```

A final JSON summary is printed to stdout.

### 3. Upload SBOMs to Dependency-Track

Configure `.env.dt`:

```text
DT_URL=<dependency-track-url>
DT_API_KEY=<api-key>
```

Then run:

```bash
uv run --env-file .env.dt ./dt_bulk_upload_sbom.py
```

Optional settings include:

```text
SBOM_DIR=~/azdo-scan/sbom
DT_DEFAULT_VERSION=HEAD
DT_AUTOCREATE=true
WAIT_FOR_PROCESSING=false
MAX_WORKERS=auto
```

### 4. Apply a package blocklist policy

The repository includes a sample policy workflow based on PURLs from `list_shai.txt`:

```bash
uv run --env-file .env.dt ./dt_create_shai_policy.py
```

The script creates a global Dependency-Track policy and attaches `MATCHES` conditions. Entries ending in `.x` are converted into regex-backed version matches.

To add conditions to an existing policy instead:

```bash
uv run --env-file .env.dt POLICY_NAME="Shai-Hulud Blocklist" ./dt_add_conditions_only.py
```

### 5. Trigger reanalysis

```bash
uv run --env-file .env.dt ./dt_trigger_reanalysis.py
```

You can also filter projects by name:

```bash
uv run --env-file .env.dt ./dt_trigger_reanalysis.py "<pattern>"
```

## Concurrency and retry controls

Large Azure DevOps projects can stress both Git endpoints and the local workstation. The scanner exposes controls including:

- `MAX_WORKERS`
- `GIT_MAX_CONCURRENCY`
- `GIT_CLONE_CONCURRENCY`
- `GIT_MAX_RETRIES`
- `HTTP_MAX_RETRIES`
- `BACKOFF_BASE_MS`
- `BACKOFF_MAX_MS`
- `START_STAGGER_MS`
- `GIT_PARTIAL_CLONE`

Defaults favour bounded network concurrency rather than starting every clone simultaneously.

## Result reuse

Set:

```text
SKIP_IF_RESULTS_EXIST=true
```

when existing SBOM and secret-scan artifacts should be reused. Individual artifacts can also be skipped when their expected result already exists.

This is useful for iterative audits, but stale artifacts are still stale evidence. Remove or regenerate outputs when repository state has materially changed.

## Security considerations

This tool handles credentials and may process sensitive source code. Treat the audit workstation and generated artifacts accordingly.

- Use a PAT with only the permissions required for repository discovery.
- Use a dedicated SSH key where practical.
- Keep `.env`, `.env.dt`, PATs, SSH private keys and Dependency-Track API keys out of Git.
- Secret-scan outputs can themselves contain sensitive material; protect them as audit evidence.
- SBOMs reveal internal package and architecture information and should not automatically be considered public.
- Review TruffleHog findings before assuming that every detector result is exploitable.
- A clean scan is not proof that a repository is secure; it only reflects the scanners, rules and repository content available during the run.

## Scope and limitations

This repository is an audit toolkit, not a complete CI/CD security platform.

It does not by itself:

- prove that every dependency is safe;
- guarantee complete secret detection;
- replace repository permissions, branch protection or build provenance controls;
- automatically remediate policy violations;
- validate runtime workloads or deployed artifacts.

Its purpose is to collect repeatable evidence that can feed a broader technical or software-supply-chain assessment.

## Troubleshooting

Common cases:

- `ModuleNotFoundError: requests` — run `uv sync`.
- SSH permission denied — verify the Azure DevOps SSH key and `ssh-agent` state.
- HTTP 429 / rate limiting — reduce concurrency or increase startup staggering.
- SSH timeouts — reduce clone concurrency and retry; the scanner already applies bounded retries to transient failures.
- Empty TruffleHog results with partial clones — fetch the required Git content or disable partial clone.

## Maintained by Omnivya

This project is part of [Omnivya](https://www.omnivya.fr/) public engineering work around platform security, SBOMs, CI/CD security and technical audits.

## License

See the repository [`LICENSE`](./LICENSE) file.
