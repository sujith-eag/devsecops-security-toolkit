# devsecops-security-toolkit

Modular toolkit for container image SBOM generation, vulnerability scanning, and basic analysis reporting.

## Current Components

- `image-sbom-vuln-scanner`  
  Generates SBOM and vulnerability scan outputs from a Docker image archive.

- `reporter-analyzer`  
  Reads scan outputs and generates:
  - `analysis-summary.json`
  - `analysis-report.md`

- `launcher/scan-image.sh`  
  Orchestrates image pull, tar creation, scan execution, and report generation.

## Project Structure

```text
.
├── image-sbom-vuln-scanner/
│   ├── Dockerfile
│   └── scan-from-tar.sh
├── reporter-analyzer/
│   ├── Dockerfile
│   └── analyzer/
└── launcher/
    └── scan-image.sh
```

## Build Images

Build scanner image:

```bash
cd image-sbom-vuln-scanner
docker build -t image-sbom-vuln-scanner:latest .
cd ..
```

Build reporter/analyzer image:

```bash
cd reporter-analyzer
docker build -t reporter-analyzer:latest .
cd ..
```

## Run Scan

Scan a public image:

```bash
./launcher/scan-image.sh nginx:latest
```

If Docker requires sudo:

```bash
sudo ./launcher/scan-image.sh nginx:latest
```

Scan another image:

```bash
sudo ./launcher/scan-image.sh ubuntu:22.04
```

Scan a locally built image:

```bash
sudo ./launcher/scan-image.sh image-sbom-vuln-scanner:latest
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

## Notes

- The launcher supports both registry images and local Docker images.
- Registry images are pulled before scanning.
- Local images are scanned without pulling.
- Image tar files are retained for 24 hours.
- Grype cache is mounted under the runtime directory to avoid repeated vulnerability DB downloads.
- Generated files are owned by the host user to avoid permission and Git ownership issues.
