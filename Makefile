APP := pkgsafe
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
VERPKG := github.com/niyam-ai/pkgsafe/internal/version
LDFLAGS := -s -w -X $(VERPKG).Version=$(VERSION) -X $(VERPKG).Commit=$(COMMIT)
DIST := dist

.PHONY: test build sbom package clean cross

test:
	go test ./...

build:
	mkdir -p $(DIST)
	go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP) ./cmd/pkgsafe

cross:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_linux_amd64 ./cmd/pkgsafe
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_darwin_amd64 ./cmd/pkgsafe
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_darwin_arm64 ./cmd/pkgsafe
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_windows_amd64.exe ./cmd/pkgsafe

package: cross
	cd $(DIST) && tar -czf $(APP)_$(VERSION)_linux_amd64.tar.gz $(APP)_linux_amd64
	cd $(DIST) && tar -czf $(APP)_$(VERSION)_darwin_amd64.tar.gz $(APP)_darwin_amd64
	cd $(DIST) && tar -czf $(APP)_$(VERSION)_darwin_arm64.tar.gz $(APP)_darwin_arm64
	cd $(DIST) && zip -q $(APP)_$(VERSION)_windows_amd64.zip $(APP)_windows_amd64.exe
	cd $(DIST) && rm -f checksums.txt && { command -v sha256sum >/dev/null && sha256sum $(APP)_* || shasum -a 256 $(APP)_*; } > checksums.txt
	$(MAKE) sbom

sbom:
	mkdir -p $(DIST)
	printf '{\n  "spdxVersion": "SPDX-2.3",\n  "dataLicense": "CC0-1.0",\n  "SPDXID": "SPDXRef-DOCUMENT",\n  "name": "pkgsafe-$(VERSION)",\n  "documentNamespace": "https://github.com/niyam-ai/pkgsafe/sbom/$(VERSION)",\n  "creationInfo": {"creators": ["Tool: PkgSafe Makefile"], "created": "1970-01-01T00:00:00Z"},\n  "packages": [{"name": "pkgsafe", "SPDXID": "SPDXRef-Package-pkgsafe", "versionInfo": "$(VERSION)", "downloadLocation": "NOASSERTION", "filesAnalyzed": false}]\n}\n' > $(DIST)/sbom.spdx.json

clean:
	rm -rf $(DIST)
