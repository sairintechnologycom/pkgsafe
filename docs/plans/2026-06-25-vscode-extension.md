# VS Code / Cursor Extension Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a VS Code/Cursor editor extension (`editors/vscode`) that connects to the local PkgSafe REST API server to dynamically scan `package.json` and `requirements.txt` files, underline high-risk dependencies with diagnostics, and show security reasons on hover.

**Architecture:** The extension will monitor active editors. When a supported file is opened or edited, it parses dependency names, queries `POST http://127.0.0.1:port/api/v1/scan` (using token authorization and configured mode), and translates `warn`/`block` decisions into VS Code `Diagnostic` objects (warnings/errors) and `Hover` tooltips.

**Tech Stack:** Node.js, TypeScript, VS Code API (`vscode`), `tsconfig.json`, `package.json`.

---

### Task 1: Extension Scaffolding
Create the directory structure, configuration manifest, and build pipeline.

**Files:**
- Create: `editors/vscode/package.json`
- Create: `editors/vscode/tsconfig.json`
- Create: `editors/vscode/src/extension.ts`
- Create: `editors/vscode/.vscodeignore`

**Step 1: Write package.json scaffold**
Define the extension package manifest.

```json
{
  "name": "pkgsafe-vscode",
  "displayName": "PkgSafe",
  "description": "Pre-installation security firewall for open-source dependencies",
  "version": "0.1.0",
  "publisher": "sairintechnologycom",
  "engines": {
    "vscode": "^1.74.0"
  },
  "categories": [
    "Linters",
    "Security"
  ],
  "activationEvents": [],
  "main": "./out/extension.js",
  "contributes": {
    "configuration": {
      "title": "PkgSafe",
      "properties": {
        "pkgsafe.enabled": {
          "type": "boolean",
          "default": true,
          "description": "Enable PkgSafe live dependency scanning."
        },
        "pkgsafe.port": {
          "type": "string",
          "default": "8080",
          "description": "Port of the local PkgSafe REST API server."
        },
        "pkgsafe.token": {
          "type": "string",
          "default": "",
          "description": "Bearer token for local PkgSafe REST API authentication."
        },
        "pkgsafe.mode": {
          "type": "string",
          "enum": ["", "audit", "warn", "block"],
          "default": "",
          "description": "Scan mode override (audit, warn, block)."
        },
        "pkgsafe.offline": {
          "type": "boolean",
          "default": false,
          "description": "Force scans to run offline using cached databases."
        }
      }
    },
    "commands": [
      {
        "command": "pkgsafe.scanActiveFile",
        "title": "PkgSafe: Scan Dependencies in Active File"
      }
    ]
  },
  "scripts": {
    "vscode:prepublish": "npm run compile",
    "compile": "tsc -p ./",
    "watch": "tsc -watch -p ./"
  },
  "devDependencies": {
    "@types/node": "^18.0.0",
    "@types/vscode": "^1.74.0",
    "typescript": "^5.0.0"
  }
}
```

**Step 2: Write tsconfig.json**
Create compile configurations.

```json
{
  "compilerOptions": {
    "module": "commonjs",
    "target": "ES2021",
    "outDir": "out",
    "lib": ["ES2021"],
    "sourceMap": true,
    "strict": true,
    "rootDir": "src",
    "esModuleInterop": true
  },
  "exclude": ["node_modules", ".vscode-test"]
}
```

**Step 3: Write extension.ts baseline**
Write a basic extension activation file that registers the manual scan command.

```typescript
import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {
    console.log('PkgSafe extension is now active!');

    let scanCmd = vscode.commands.registerCommand('pkgsafe.scanActiveFile', () => {
        vscode.window.showInformationMessage('PkgSafe manual scan triggered.');
    });

    context.subscriptions.push(scanCmd);
}

export function deactivate() {}
```

**Step 4: Build to verify setup**
Run: `cd editors/vscode && npm install && npm run compile`
Expected: Compile succeeds with no errors, and `editors/vscode/out/extension.js` is generated.

**Step 5: Commit**
```bash
git add editors/vscode/
git commit -m "feat(editors/vscode): scaffold extension project structure"
```

---

### Task 2: Dependency Parsers
Create utilities to parse dependency name/version and range positions in `package.json` and `requirements.txt`.

**Files:**
- Create: `editors/vscode/src/parser.ts`
- Create: `editors/vscode/src/test/parser.test.ts`

**Step 1: Write parser logic**
Implement JSON parsing for `package.json` dependencies and regex parsing for `requirements.txt` packages.

```typescript
import * as vscode from 'vscode';

export interface Dependency {
    ecosystem: 'npm' | 'pypi';
    name: string;
    version: string;
    range: vscode.Range;
}

export function parsePackageJson(document: vscode.TextDocument): Dependency[] {
    const deps: Dependency[] = [];
    const text = document.getText();
    try {
        const obj = JSON.parse(text);
        const sections = ['dependencies', 'devDependencies'];
        for (const sec of sections) {
            if (obj[sec] && typeof obj[sec] === 'object') {
                for (const [name, verSpec] of Object.entries(obj[sec])) {
                    if (typeof verSpec !== 'string') continue;
                    // Find name range
                    const nameIdx = text.indexOf(`"${name}"`);
                    if (nameIdx !== -1) {
                        const startPos = document.positionAt(nameIdx + 1);
                        const endPos = document.positionAt(nameIdx + 1 + name.length);
                        deps.push({
                            ecosystem: 'npm',
                            name,
                            version: cleanVersion(verSpec),
                            range: new vscode.Range(startPos, endPos)
                        });
                    }
                }
            }
        }
    } catch {}
    return deps;
}

export function parseRequirementsTxt(document: vscode.TextDocument): Dependency[] {
    const deps: Dependency[] = [];
    const lineCount = document.lineCount;
    for (let i = 0; i < lineCount; i++) {
        const line = document.lineAt(i);
        const text = line.text.trim();
        if (text === '' || text.startsWith('#')) continue;

        // Matches package==version or package>=version or similar
        const match = text.match(/^([a-zA-Z0-9_\-\[\]]+)(==|>=|<=|>|<|~=)?(.*)$/);
        if (match) {
            const name = match[1].trim();
            const ver = match[3] ? match[3].trim().split(' ')[0] : '';
            const startChar = line.text.indexOf(name);
            const startPos = new vscode.Position(i, startChar);
            const endPos = new vscode.Position(i, startChar + name.length);
            deps.push({
                ecosystem: 'pypi',
                name,
                version: ver,
                range: new vscode.Range(startPos, endPos)
            });
        }
    }
    return deps;
}

function cleanVersion(v: string): string {
    return v.replace(/^[\^~>=<]+/g, '').trim();
}
```

**Step 2: Run test compilation**
Run: `npm run compile` in `editors/vscode`
Expected: Compile succeeds

**Step 3: Commit**
```bash
git add editors/vscode/src/parser.ts
git commit -m "feat(editors/vscode): add package.json and requirements.txt dependency parsers"
```

---

### Task 3: API Client & Diagnostic Provider
Implement HTTP requests to the local server, diagnostics creation, hover presentation, and active editor change tracking.

**Files:**
- Modify: `editors/vscode/src/extension.ts`

**Step 1: Write Client & Diagnostic code**
Implement HTTP POST queries to `http://127.0.0.1:port/api/v1/scan` and map high-risk results to diagnostics and hovers.

```typescript
import * as vscode from 'vscode';
import * as http from 'http';
import { parsePackageJson, parseRequirementsTxt, Dependency } from './parser';

interface ScanResult {
    decision: 'allow' | 'warn' | 'block';
    score: number;
    reasons: Array<{
        id: string;
        severity: string;
        score_impact: number;
        description: string;
    }>;
    recommended_action?: string;
}

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('pkgsafe');
    context.subscriptions.push(diagnosticCollection);

    const scanActive = async (document: vscode.TextDocument) => {
        const config = vscode.workspace.getConfiguration('pkgsafe');
        if (!config.get<boolean>('enabled', true)) {
            diagnosticCollection.clear();
            return;
        }

        let deps: Dependency[] = [];
        if (document.fileName.endsWith('package.json')) {
            deps = parsePackageJson(document);
        } else if (document.fileName.endsWith('requirements.txt')) {
            deps = parseRequirementsTxt(document);
        }

        if (deps.length === 0) return;

        const diagnostics: vscode.Diagnostic[] = [];
        const promises = deps.map(async (dep) => {
            try {
                const res = await queryScanAPI(dep, config);
                if (res && (res.decision === 'warn' || res.decision === 'block')) {
                    const sev = res.decision === 'block' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning;
                    const msg = `[PkgSafe ${res.decision.toUpperCase()}] Risk Score: ${res.score}/100\nReasons:\n` +
                        res.reasons.map(r => `- [${r.severity}] ${r.description}`).join('\n') +
                        (res.recommended_action ? `\n\nRecommendation: ${res.recommended_action}` : '');
                    
                    const diag = new vscode.Diagnostic(dep.range, msg, sev);
                    diag.code = dep.ecosystem;
                    diagnostics.push(diag);
                }
            } catch (err) {
                console.error(`PkgSafe scan failed for ${dep.name}:`, err);
            }
        });

        await Promise.all(promises);
        diagnosticCollection.set(document.uri, diagnostics);
    };

    // Trigger on open/save/change
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(doc => scanActive(doc)),
        vscode.workspace.onDidSaveTextDocument(doc => scanActive(doc)),
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) scanActive(editor.document);
        })
    );

    // Register Hover Provider
    const hoverProvider = vscode.languages.registerHoverProvider(
        [
            { pattern: '**/package.json', scheme: 'file' },
            { pattern: '**/requirements.txt', scheme: 'file' }
        ],
        {
            provideHover(document, position) {
                const diags = diagnosticCollection.get(document.uri) || [];
                for (const diag of diags) {
                    if (diag.range.contains(position)) {
                        const markdown = new vscode.MarkdownString();
                        markdown.appendMarkdown(`### 🛡️ PkgSafe Security Alert\n\n${diag.message}`);
                        markdown.isTrusted = true;
                        return new vscode.Hover(markdown, diag.range);
                    }
                }
                return undefined;
            }
        }
    );
    context.subscriptions.push(hoverProvider);

    // Manual scan command
    let scanCmd = vscode.commands.registerCommand('pkgsafe.scanActiveFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: "PkgSafe: Scanning dependencies...",
                cancellable: false
            }, async () => {
                await scanActive(editor.document);
            });
        }
    });
    context.subscriptions.push(scanCmd);

    // Initial run
    if (vscode.window.activeTextEditor) {
        scanActive(vscode.window.activeTextEditor.document);
    }
}

function queryScanAPI(dep: Dependency, config: vscode.WorkspaceConfiguration): Promise<ScanResult | null> {
    return new Promise((resolve, reject) => {
        const port = config.get<string>('port', '8080');
        const token = config.get<string>('token', '');
        const mode = config.get<string>('mode', '');
        const offline = config.get<boolean>('offline', false);

        const data = JSON.stringify({
            ecosystem: dep.ecosystem,
            name: dep.name,
            version: dep.version,
            mode: mode || undefined,
            offline: offline
        });

        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data).toString()
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const req = http.request({
            hostname: '127.0.0.1',
            port: parseInt(port),
            path: '/api/v1/scan',
            method: 'POST',
            headers: headers,
            timeout: 5000
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    try {
                        resolve(JSON.parse(body) as ScanResult);
                    } catch {
                        resolve(null);
                    }
                } else {
                    resolve(null);
                }
            });
        });

        req.on('error', err => reject(err));
        req.write(data);
        req.end();
    });
}
```

**Step 2: Build & Verify**
Run: `npm run compile`
Expected: Compile succeeds

**Step 3: Commit**
```bash
git add editors/vscode/src/extension.ts
git commit -m "feat(editors/vscode): implement client request, diagnostics, and hover provider"
```
