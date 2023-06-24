import * as vscode from 'vscode';

import { Report } from '../tree_types';
import { FlowItem } from './flow_item';
import { SourceItem } from './source_item';
import { RuleItem } from './rule_item';

export class ReportItem extends vscode.TreeItem {
    // children represent branches, which are also items
    readonly rule: RuleItem;
    readonly source: SourceItem;

    public children: FlowItem[] = [];

    private labelStr: string;
    // keep track of the original YAML report, as parsing looses information
    // on inlines.
    public report: Report;
    private _toString: string = "";
    private isActive: boolean = true;

    // add all members here, file and line we'll need later
    // the label represent the text which is displayed in the tree
    // and is passed to the base class
    constructor(rule: RuleItem, source: SourceItem, yamlReport: Report) {
        let label = yamlReport.flow[0]?.func + " -> " +
            yamlReport.flow[yamlReport.flow.length - 1]?.func;
        super(label, vscode.TreeItemCollapsibleState.None);
        this.rule = rule;
        this.report = yamlReport;
        this.source = source;
        this.description = "";
        this.labelStr = label;
        this.collapsibleState = vscode.TreeItemCollapsibleState.None;
    }

    // a public method to add childs, and with additional branches
    // we want to make the item collabsible
    public addFlow(child: FlowItem) {
        this.collapsibleState = vscode.TreeItemCollapsibleState.Collapsed;
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
        this.isActive = true;
        this.report.type = '';
        this.contextValue = "report";
    }

    public deactivate(type: string) {
        if (!this.isActive) {
            return;
        }
        // update labels
        this.description = this.labelStr;
        this.label = "~";
        this.labelStr = "~" + this.labelStr;
        this.isActive = false;
        this.report.type = type;
    }


    public export() {
        return this.report;
    }
}
