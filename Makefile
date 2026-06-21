APP := pkgsafe
VERSION ?= 0.1.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo local)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
DIST := dist

.PHONY: test build package clean cross

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

clean:
	rm -rf $(DIST)
