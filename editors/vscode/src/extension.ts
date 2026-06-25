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

export function deactivate() {}
