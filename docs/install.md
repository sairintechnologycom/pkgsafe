# Install PkgSafe

PkgSafe is distributed as a single static binary. PkgSafe v1.0.0 is npm-first
GA: npm package scanning, package-lock scanning, CI gating, policies, OSV
intelligence, and evidence reports are the production scope. PyPI, Go, and
Cargo coverage is preview and should not be treated as npm-equivalent.

Use the published release artifacts for normal installs. The examples below pin
v1.0.0; replace `VERSION` only when intentionally installing a newer release.

## macOS arm64

```bash
VERSION=1.0.0
OS=darwin
ARCH=arm64
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mv pkgsafe /usr/local/bin/pkgsafe
pkgsafe version
pkgsafe doctor
```

## macOS amd64

```bash
VERSION=1.0.0
OS=darwin
ARCH=amd64
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mv pkgsafe /usr/local/bin/pkgsafe
pkgsafe version
pkgsafe doctor
```

## Linux amd64

```bash
VERSION=1.0.0
OS=linux
ARCH=amd64
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mv pkgsafe /usr/local/bin/pkgsafe
pkgsafe version
pkgsafe doctor
```

## Windows zip

Run from PowerShell:

```powershell
$Version = "1.0.0"
$Os = "windows"
$Arch = "amd64"
$Archive = "pkgsafe_${Version}_${Os}_${Arch}.zip"
Invoke-WebRequest -Uri "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${Version}/${Archive}" -OutFile $Archive
Expand-Archive -Path $Archive -DestinationPath .
.\pkgsafe.exe version
.\pkgsafe.exe doctor
```

Move `pkgsafe.exe` into a directory on your `PATH` after verification.

## Verify The Release

Download the archive, checksums, cosign signature, and signing certificate into
the same directory:

```bash
VERSION=1.0.0
OS=linux
ARCH=amd64
ARCHIVE="pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}"

curl -LO "${BASE_URL}/${ARCHIVE}"
curl -LO "${BASE_URL}/checksums.txt"
curl -LO "${BASE_URL}/checksums.txt.sig"
curl -LO "${BASE_URL}/checksums.txt.pem"
```

Verify checksums:

```bash
# Linux
sha256sum -c checksums.txt

# macOS
shasum -a 256 -c checksums.txt
```

Verify the cosign keyless signature over `checksums.txt`:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Verify GitHub Artifact Attestation provenance for the archive:

```bash
gh attestation verify "${ARCHIVE}" --repo sairintechnologycom/pkgsafe
```

Extract and run the binary:

```bash
tar -xzf "${ARCHIVE}"
./pkgsafe version
./pkgsafe doctor
```

A v1.0.0 release build reports a version line in this shape:

```text
pkgsafe v1.0.0 (<commit>)
```

Local development builds may report a `-dev` version or `none` commit instead.

For the complete verification guide, including SBOM checks, see
[release-verification.md](release-verification.md).

## Behavior Analysis Note

Behavior analysis is disabled by default. `--behavior heuristic` and the
deprecated `--sandbox` compatibility input execute lifecycle scripts on the host
without OS isolation; they are not sandboxing or containment. Use them only in
disposable environments.
