# Install PkgSafe

PkgSafe is one static binary. **GA:** npm and PyPI. **Preview:** Go and Cargo.

New users: [getting-started.md](getting-started.md) · full docs index:
[README.md](README.md).

Use official release artifacts for production. Examples below pin **v1.6.0**;
change `VERSION` only when you mean to.

### Homebrew (macOS & Linux — recommended)

```bash
brew install sairintechnologycom/pkgsafe/pkgsafe
```

Upgrade later with `brew upgrade pkgsafe`.

### One-line installer

```bash
curl -fsSL https://github.com/sairintechnologycom/pkgsafe/releases/latest/download/install.sh | bash
pkgsafe doctor
```

Optional: `PKGSAFE_VERSION=1.6.0` · `PKGSAFE_BIN_DIR=$HOME/.local/bin`.

---

## Manual install by platform

## macOS arm64

```bash
VERSION=1.6.0
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
VERSION=1.6.0
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
VERSION=1.6.0
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
$Version = "1.6.0"
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
VERSION=1.6.0
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

A v1.6.0 release build reports a version line in this shape:

```text
pkgsafe v1.6.0 (<commit>)
```

Local development builds may report a `-dev` version or `none` commit instead.

For the complete verification guide, including SBOM checks, see
[release-verification.md](release-verification.md).

## Behavior Analysis Note

Behavior analysis is disabled by default. `--behavior heuristic` and the
deprecated `--sandbox` compatibility input execute lifecycle scripts on the host
without OS isolation; they are not sandboxing or containment. Use them only in
disposable environments.
