# DevSecOps Security Toolkit

A Modular DevSecOps toolkit for generating SBOMs, scanning vulnerabilities, creating organization-level security/dependecy data, and viewing the results through a centralized security dashboard.

## Main Capabilities

- Scan container images and source projects
- Generate CycloneDX SBOMs
- Run vulnerability scans
- Normalize SBOM and vulnerability data into reusable org-level data
- Build query indexes for artifacts, packages, vulnerabilities, and remediation
- View results in a local web console
- Generate simple security/remediation reports

## Repository Structure

```text
devsecops-security-toolkit/
├── launcher/
│   ├── scan.sh
│   ├── generate-org-data.sh
│   └── run-security-console.sh
├── image-sbom-vuln-scanner/
├── reporter-analyzer/
├── org-data-generator/
└── org-security-console/
```

## Main Modules

### `image-sbom-vuln-scanner`

Generates SBOMs and vulnerability scan output for container images and source folders.

Responsibilities:

- generate CycloneDX SBOM
- run Grype against image/SBOM
- write raw scanner outputs

### `reporter-analyzer`

Creates analysis outputs from raw scan data.

Responsibilities:

- summarize scan findings
- generate analysis reports

### `org-data-generator`

Creates normalized current-state organization security data.

Responsibilities:

- parse metadata and SBOMs
- normalize projects, artifacts, packages, vulnerabilities
- create relationships and indexes
- refresh SBOM vulnerability scans when enabled

### `org-security-console`

Local web console for querying and viewing generated org data.

Responsibilities:

- read `org-data/current`
- show dashboard views
- provide remediation and detail pages
- generate Markdown reports

## Runtime Data

By default, runtime data is stored under: `~/image-scanner-runtime/`

This can be overridden with: `IMAGE_SCANNER_BASE_DIR=/custom/path`

Main runtime folders:

```text
~/image-scanner-runtime/
├── results/          # raw per-artifact scan outputs
├── cache/            # tool caches, including Grype DB
├── org-data/         # normalized organization security data
├── security-reports/ # generated reports
└── logs/
```

## Typical Workflow

### 1. Scan a Artifact

Scan an image :

```bash
sudo ./launcher/scan.sh image nginx:latest
```

Scan a source repo :

```bash
sudo ./launcher/scan.sh source sbom-vuln-scanner:latest
```

This creates a result folder under:

```text
~/image-scanner-runtime/results/
```

Each result folder contains files such as:

```text
metadata.json
sbom-cyclonedx.json
grypе-sbom-vulns.json
grypе-image-vulns.json
```

### 2. Generate normalized org data

```bash
sudo ./launcher/generate-org-data.sh
```

This reads all result folders and writes normalized data to:

```text
~/image-scanner-runtime/org-data/current/
```

The output includes:

```text
entities/
relationships/
indexes/
run/
```

To skip refreshing SBOM vulnerabilities.

```bash
sudo SKIP_VULN_REFRESH=true ./launcher/generate-org-data.sh
```

### 3. Start the local security console

```bash
sudo ./launcher/run-security-console.sh
```

Open:

```text
http://localhost:8090
```

The console provides views for:

- overview
- remediation
- artifacts
- vulnerabilities
- packages
- reports


## Build Images

Build scanner image:

```bash
cd image-sbom-vuln-scanner
docker build -t image-sbom-vuln-scanner:latest .
```

Build reporter/analyzer image:

```bash
cd reporter-analyzer
docker build -t reporter-analyzer:latest .
```


```bash
docker build -t org-data-generator:latest ./org-data-generator

docker build -t org-security-console:latest ./org-security-console
```

## Runtime Output

Default runtime directory:

```text
~/image-scanner-runtime/
```

Override runtime directory:

```bash
export IMAGE_SCANNER_BASE_DIR=/custom/path/image-scanner-runtime
```

Example result structure:

```text
~/image-scanner-runtime/results/nginx_latest__sha256_xxxxx/
├── metadata.json
├── sbom-cyclonedx.json
├── grype-image-vulns.json
├── grype-image-vulns.table.txt
├── grype-sbom-vulns.json
├── grype-sbom-vulns.table.txt
├── scanner-tool-versions.txt
├── scanner-scan.log
├── host-scan.log
└── analysis/
    ├── analysis-summary.json
    └── analysis-report.md
```
