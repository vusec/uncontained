import * as vscode from 'vscode';

import { RuleItem } from './rule_item';
import { ReportItem } from './report_item';

export class SourceItem extends vscode.TreeItem {
    readonly source: string;

    public labelStr: string;
    public rule: RuleItem;

    private isActive: boolean = true;
    private _toString: string = "";

    // children represent branches, which are also items
    public children: ReportItem[] = [];

    constructor(source: string, rule: RuleItem) {
        super(source, vscode.TreeItemCollapsibleState.None);
        this.source = source;
        this.rule = rule;
        this.collapsibleState = vscode.TreeItemCollapsibleState.None;
        this.labelStr = source;
        this.contextValue = "source";
    }

    public addReport(child: ReportItem) {
        this.collapsibleState = vscode.TreeItemCollapsibleState.Expanded;
        this.children.push(child);
        if (this._toString.length) {
            this._toString += ",";
        }
        this._toString += child.toString();
    }

    public toString() {
        return this._toString;
    }

    public activate() {
        if (this.isActive) {
            return;
        }
        // update labels
        this.label = this.description?.toString();
        this.labelStr = this.description?.toString() || "";
        this.description = "";
        this.contextValue = "source";
        this.isActive = true;

        for (const child of this.children) {
            child.activate();
        }
    }

    public deactivate() {
        if (!this.isActive) {
            return;
        }
        // update labels
        this.description = this.labelStr;
        this.label = "~";
        this.labelStr = "~" + this.labelStr;
        this.contextValue = "sourceInactive";
        this.isActive = false;

        for (const child of this.children) {
            child.deactivate('inactive');
        }
    }

    public makeFP() {
        if (!this.isActive) {
            return;
        }
        // update labels
        this.description = this.labelStr;
        this.label = "~FP";
        this.labelStr = "~FP" + this.labelStr;
        this.contextValue = "sourceInactive";
        this.isActive = false;

        for (const child of this.children) {
            child.deactivate('FP');
        }
    }
}
