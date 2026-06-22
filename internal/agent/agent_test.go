package agent

import (
	"testing"
)

func TestParseInstallCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		want    []ParsedPackage
		wantErr bool
	}{
		{
			name: "simple install",
			cmd:  "npm install axios",
			want: []ParsedPackage{
				{Name: "axios", Version: "latest"},
			},
		},
		{
			name: "npm i alias",
			cmd:  "npm i lodash",
			want: []ParsedPackage{
				{Name: "lodash", Version: "latest"},
			},
		},
		{
			name: "npm add",
			cmd:  "npm add react",
			want: []ParsedPackage{
				{Name: "react", Version: "latest"},
			},
		},
		{
			name: "with version tag",
			cmd:  "npm install axios@1.6.0",
			want: []ParsedPackage{
				{Name: "axios", Version: "1.6.0"},
			},
		},
		{
			name: "multiple packages with flags",
			cmd:  "npm install axios lodash --save-dev -g -E --force",
			want: []ParsedPackage{
				{Name: "axios", Version: "latest"},
				{Name: "lodash", Version: "latest"},
			},
		},
		{
			name: "scoped packages",
			cmd:  "npm install @types/node@18.0.0",
			want: []ParsedPackage{
				{Name: "@types/node", Version: "18.0.0"},
			},
		},
		{
			name:    "empty command",
			cmd:     "npm install",
			wantErr: true,
		},
		{
			name:    "unsupported command",
			cmd:     "yarn add lodash",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInstallCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseInstallCommand() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d packages, got %d", len(tt.want), len(got))
			}
			for i := range got {
				if got[i].Name != tt.want[i].Name || got[i].Version != tt.want[i].Version {
					t.Errorf("got[%d] = %v, want[%d] = %v", i, got[i], i, tt.want[i])
				}
			}
		})
	}
}

func TestCheckAISquatting(t *testing.T) {
	tests := []struct {
		name        string
		pkgName     string
		description string
		repository  any
		hasScripts  bool
		ageDays     int
		want        bool
	}{
		{
			name:        "normal popular package",
			pkgName:     "react",
			description: "A JavaScript library for building user interfaces",
			repository:  "https://github.com/facebook/react",
			hasScripts:  false,
			ageDays:     3650,
			want:        false,
		},
		{
			name:        "classic AI squatting name with low quality indicators",
			pkgName:     "react-markdown-renderer-plus",
			description: "",
			repository:  nil,
			hasScripts:  true,
			ageDays:     2,
			want:        true,
		},
		{
			name:        "ends with suffix but has repository and description",
			pkgName:     "react-pro",
			description: "An official pro version with source code repository",
			repository:  "https://github.com/example/react-pro",
			hasScripts:  false,
			ageDays:     100,
			want:        false,
		},
		{
			name:        "generic suffix with high signals",
			pkgName:     "custom-squatting-pro",
			description: "too short",
			repository:  nil,
			hasScripts:  true,
			ageDays:     5,
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckAISquatting(tt.pkgName, tt.description, tt.repository, tt.hasScripts, tt.ageDays)
			if got != tt.want {
				t.Errorf("CheckAISquatting() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSafeAlternatives(t *testing.T) {
	t.Run("curated match", func(t *testing.T) {
		alts := GetSafeAlternatives("react-markdown-renderer-plus")
		if len(alts) != 2 {
			t.Fatalf("expected 2 alternatives, got %d", len(alts))
		}
		if alts[0].Name != "react-markdown" || alts[1].Name != "markdown-it" {
			t.Errorf("unexpected alternatives: %v", alts)
		}
	})

	t.Run("dynamic match", func(t *testing.T) {
		alts := GetSafeAlternatives("lodash-plus")
		if len(alts) != 1 {
			t.Fatalf("expected 1 alternative, got %d", len(alts))
		}
		if alts[0].Name != "lodash" {
			t.Errorf("expected lodash, got %s", alts[0].Name)
		}
	})

	t.Run("no match", func(t *testing.T) {
		alts := GetSafeAlternatives("axios")
		if len(alts) != 0 {
			t.Errorf("expected no alternatives, got %v", alts)
		}
	})
}
