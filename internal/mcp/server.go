package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ValidateParams struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

func Serve(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	enc := json.NewEncoder(w)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(Response{JSONRPC: "2.0", Error: &Error{Code: -32700, Message: err.Error()}})
			continue
		}
		resp := handle(req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handle(req Request) Response {
	switch req.Method {
	case "ping":
		return Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"ok": true}}
	case "tools/list":
		return Response{JSONRPC: "2.0", ID: req.ID, Result: []map[string]any{
			{"name": "validate_package_install", "description": "Validate an npm package before install"},
		}}
	case "validate_package_install":
		var p ValidateParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, -32602, err.Error())
		}
		if p.Ecosystem == "" {
			p.Ecosystem = "npm"
		}
		if p.Ecosystem != "npm" {
			return errResp(req.ID, -32602, "only npm is supported in this MVP")
		}
		if p.Name == "" {
			return errResp(req.ID, -32602, "name is required")
		}
		res, err := snpm.ScanPackage(p.Name, p.Version)
		if err != nil {
			return errResp(req.ID, -32000, fmt.Sprintf("npm scan failed: %v", err))
		}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: res}
	default:
		return errResp(req.ID, -32601, "method not found")
	}
}

func errResp(id any, code int, msg string) Response {
	return Response{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
}
