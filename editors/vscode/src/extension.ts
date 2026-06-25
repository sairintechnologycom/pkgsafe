import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {
    console.log('PkgSafe extension is now active!');

    let scanCmd = vscode.commands.registerCommand('pkgsafe.scanActiveFile', () => {
        vscode.window.showInformationMessage('PkgSafe manual scan triggered.');
    });

    context.subscriptions.push(scanCmd);
}

export function deactivate() {}
