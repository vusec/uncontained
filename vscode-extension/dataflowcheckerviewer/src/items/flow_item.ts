import * as vscode from 'vscode';
import { ReportItem } from './report_item';

export class FlowItem extends vscode.TreeItem {
    readonly func: string;
    readonly file: string;
    readonly line: number;
    readonly report: ReportItem;

    constructor(report: ReportItem, func: string, file: string, line: number) {
        super(func, vscode.TreeItemCollapsibleState.None);
        this.report = report;
        this.func = func;
        this.file = file;
        this.line = line;
        this.description = file + ":" + line;
        this.tooltip = func + " at " + file + ":" + line;
        this.collapsibleState = vscode.TreeItemCollapsibleState.None;

        this.command = { command: 'dataflow_view.itemClicked', title : "view: " + func, arguments: [this] };
    }

    public toString() {
        return this.description as string;
    }
}
