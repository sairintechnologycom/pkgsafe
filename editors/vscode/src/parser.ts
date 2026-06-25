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
