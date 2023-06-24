import * as vscode from 'vscode';

import { SourceItem } from './source_item';

export class RuleItem extends vscode.TreeItem {
    readonly rule: string;

    public nameToSource: Record<string, SourceItem> = {};

    // children represent branches, which are also items
    public children: SourceItem[] = [];

    constructor(rule: string) {
        super(rule, vscode.TreeItemCollapsibleState.None);
        this.rule = rule;
        this.collapsibleState = vscode.TreeItemCollapsibleState.None;
    }

    public addSource(child: SourceItem) {
        this.collapsibleState = vscode.TreeItemCollapsibleState.Expanded;
        this.children.push(child);
        this.refreshTitle();
    }

    public refreshTitle() {
        const disabled = this.children.filter((source) => source.labelStr.startsWith("~"));
        const tpCount = this.children.length - disabled.length;
        const fpCount = disabled.length;

        this.label = `${this.rule} (${this.children.length}, TP: ${tpCount}, FP: ${fpCount})`;
    }

    public sortSources() {
        const disabled = this.children.filter((source) => source.labelStr.startsWith("~"));
        const active = this.children.filter((source) => !source.labelStr.startsWith("~"));
        disabled.sort((a, b) => a.labelStr.localeCompare(b.labelStr));
        active.sort((a, b) => a.labelStr.localeCompare(b.labelStr));
        this.children = disabled.concat(active);
        this.refreshTitle();
    }
}
