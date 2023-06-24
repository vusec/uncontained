// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { dataflow } from './tree_view';

import { SourceItem } from './items/source_item';
import { ReportItem } from './items/report_item';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	//create a local tree view and register it in vscode
	let tree = new dataflow.TreeView(context);
	vscode.window.registerTreeDataProvider('dataflow_view', tree);

	vscode.window.onDidChangeActiveTextEditor(() => {
		const editor = vscode.window.activeTextEditor;
		if (editor === undefined) {
			return;
		}
		const fileName = editor.document.fileName;
		tree.highlight(editor, fileName);
	});

	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.parseReportFile', () => {
		tree.refresh();
	}));
	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.deactivate', () => {
		tree.deactivate();
	}));
	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.showReport', (report: ReportItem) => {
		tree.showReport(report);
	}));
	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.makeActive', (source: SourceItem) => {
		tree.makeActive(source);
	}));
	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.makeInactive', (source: SourceItem) => {
		tree.makeInactive(source);
	}));
	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.makeFP', (source: SourceItem) => {
		tree.makeFP(source);
	}));
	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.showCache', (report: ReportItem) => {
		tree.showInactive();
	}));
	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.resetCache', (report: ReportItem) => {
		tree.clearInactive();
	}));
	context.subscriptions.push(vscode.commands.registerCommand('dataflow_view.export', () => {
		tree.export();
	}));

}

// This method is called when your extension is deactivated
export function deactivate() { }
