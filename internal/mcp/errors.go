package mcp

import (
	"strings"
)

// ToolError defines the standard structured error JSON format for PkgSafe MCP tool failures.
type ToolError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details any    `json:"details,omitempty"`
	} `json:"error"`
}

// MapScanError maps standard errors to structured ToolError instances.
func MapScanError(err error, ecosystem, name, version string) ToolError {
	var code string
	var msg string

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "404") || strings.Contains(errStr, "not found") || strings.Contains(errStr, "status 404") || strings.Contains(errStr, "npm registry returned"):
		code = "PACKAGE_NOT_FOUND"
		msg = "Package not found in npm registry"
	case strings.Contains(errStr, "offline scan failed"):
		code = "OFFLINE_CACHE_MISSING"
		msg = "Offline cache missing for this package"
	case strings.Contains(errStr, "dial tcp") || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "connection refused"):
		code = "REGISTRY_UNAVAILABLE"
		msg = "Registry unavailable"
	case strings.Contains(errStr, "load policy") || strings.Contains(errStr, "parse policy") || strings.Contains(errStr, "invalid policy"):
		code = "POLICY_LOAD_FAILURE"
		msg = "Failed to load policy"
	case strings.Contains(errStr, "lockfile") || strings.Contains(errStr, "no such file or directory"):
		code = "LOCKFILE_NOT_FOUND"
		msg = "Lockfile not found"
	default:
		code = "INTERNAL_SCAN_FAILURE"
		msg = "Internal scan failure: " + errStr
	}

	te := ToolError{}
	te.Error.Code = code
	te.Error.Message = msg
	te.Error.Details = map[string]string{
		"ecosystem": ecosystem,
		"package":   name,
		"version":   version,
	}
	return te
}
