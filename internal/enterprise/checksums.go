package enterprise

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func ComputeSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func VerifyChecksums(files map[string][]byte, checksumsContent string) error {
	expected := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(checksumsContent))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			// standard sha256sum format: <checksum>  <filename>
			// or <filename>: <checksum>
			if strings.HasSuffix(parts[0], ":") {
				filename := strings.TrimSuffix(parts[0], ":")
				expected[filename] = parts[1]
			} else {
				expected[parts[1]] = parts[0]
			}
		} else if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			expected[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	for filename, content := range files {
		if filename == "checksums.txt" || filename == "signature.sig" {
			continue
		}
		expSum, ok := expected[filename]
		if !ok {
			// try base name
			expSum, ok = expected[strings.TrimPrefix(filename, "./")]
			if !ok {
				return fmt.Errorf("missing checksum for file: %s", filename)
			}
		}
		h := sha256.New()
		h.Write(content)
		actualSum := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(actualSum, expSum) {
			return fmt.Errorf("checksum mismatch for file %s: expected %s, got %s", filename, expSum, actualSum)
		}
	}
	return nil
}
