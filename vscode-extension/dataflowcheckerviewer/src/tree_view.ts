import { spawn } from 'child_process';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import * as path from 'path';
import * as rd from 'readline';
import * as vscode from 'vscode';
import { Reports, Report, Flow, flowsEqual } from './tree_types';

import { SourceItem } from './items/source_item';
import { RuleItem } from './items/rule_item';
import { ReportItem } from './items/report_item';
import { FlowItem } from './items/flow_item';

export const INACTIVE_SOURCES_KEY = "dataflow_inactive_sources";
export const FP_SOURCES_KEY = "dataflow_fp_sources";

// lets put all in a dataflow namespace
export namespace dataflow {
    export class TreeView implements vscode.TreeDataProvider<RuleItem>
    {
        private context: vscode.ExtensionContext;
        private mData: RuleItem[] = [];
        private nameToItem: Record<string, RuleItem> = {};

        // the base path where that reports shown refers to
        private reportPath: string = ".";
        private reportFile: string = "";

        private activeReport: ReportItem | undefined = undefined;
        public highlightRangePerFile: Record<string, vscode.Range[]> = {};

        // highlight dataflow
        readonly decoration: vscode.TextEditorDecorationType;

        // saved inactive entries representation
        private inactiveSources: Set<string>;

        // saved fp entries representation
        private fpSources: Set<string>;

        // with the vscode.EventEmitter we can refresh our  tree view
        private mOnDidChangeTreeData: vscode.EventEmitter<RuleItem | undefined> = new vscode.EventEmitter<RuleItem | undefined>();
        // and vscode will access the event by using a readonly onDidChangeTreeData (this member has to be named like here, otherwise vscode doesnt update our treeview.
        readonly onDidChangeTreeData?: vscode.Event<RuleItem | undefined> = this.mOnDidChangeTreeData.event;

        public constructor(context: vscode.ExtensionContext) {
            this.context = context;
            vscode.commands.registerCommand('dataflow_view.itemClicked', r => this.itemClicked(r));

            this.decoration = vscode.window.createTextEditorDecorationType({
                backgroundColor: 'rgba(212, 175, 55, 0.3)',
                isWholeLine: true,
                overviewRulerColor: 'rgba(212, 175, 55, 0.8)'
            });

            const workspaceState: vscode.Memento = this.context.workspaceState;
            const savedInactive = workspaceState.get(INACTIVE_SOURCES_KEY);
            if (!savedInactive  || Object.keys(savedInactive as object).length === 0) {
                this.inactiveSources = new Set<string>();
            } else {
                this.inactiveSources = new Set<string>(savedInactive as Array<string>);
            }
            const savedFP = workspaceState.get(FP_SOURCES_KEY);
            if (!savedFP  || Object.keys(savedFP as object).length === 0) {
                this.fpSources = new Set<string>();
            } else {
                this.fpSources = new Set<string>(savedFP as Array<string>);
            }
        }

        // we need to implement getTreeItem to receive items from our tree view
        public getTreeItem(element: vscode.TreeItem): vscode.TreeItem | Thenable<vscode.TreeItem> {
            // const item = new vscode.TreeItem(element.label!, element.collapsibleState);
            // item.description = element.description;
            // item.tooltip = element.tooltip;
            return element;
        }

        // and getChildren
        public getChildren(element: any | undefined): vscode.ProviderResult<RuleItem[]> {
            if (element === undefined) {
                return this.mData;
            } else {
                return element.children;
            }
        }

        public showReport(report: ReportItem) {
            // emulate click on sink
            this.itemClicked(report.children[report.children.length - 1]);
        }

        // cache active if updated
        public maybeCacheActive(source: SourceItem) {
            // cache inactive if updated
            const sourceString = source.toString();
            if (this.inactiveSources.has(sourceString)) {
                this.inactiveSources.delete(sourceString);
                const workspaceState: vscode.Memento = this.context.workspaceState;
                workspaceState.update(INACTIVE_SOURCES_KEY, Array.from(this.inactiveSources));
            }
            if (this.fpSources.has(sourceString)) {
                this.fpSources.delete(sourceString);
                const workspaceState: vscode.Memento = this.context.workspaceState;
                workspaceState.update(FP_SOURCES_KEY, Array.from(this.fpSources));
            }
        }

        // cache inactive if updated
        public maybeCacheInactive(source: SourceItem) {
            // cache inactive if updated
            const reportString = source.toString();
            if (!this.inactiveSources.has(reportString)) {
                this.inactiveSources.add(reportString);
                const workspaceState: vscode.Memento = this.context.workspaceState;
                workspaceState.update(INACTIVE_SOURCES_KEY, Array.from(this.inactiveSources));
            }
        }

        // cache FP if updated
        public maybeCacheFP(source: SourceItem) {
            // cache inactive if updated
            const reportString = source.toString();
            if (!this.fpSources.has(reportString)) {
                this.fpSources.add(reportString);
                const workspaceState: vscode.Memento = this.context.workspaceState;
                workspaceState.update(FP_SOURCES_KEY, Array.from(this.fpSources));
            }
        }

        public makeActive(source: SourceItem) {
            source.activate();
            // sort the entries again
            source.rule.sortSources();

            this.maybeCacheActive(source);
            this.mOnDidChangeTreeData.fire(undefined);
        }

        public makeInactive(source: SourceItem) {
            source.deactivate();
            // sort the entries again
            source.rule.sortSources();

            this.maybeCacheInactive(source);
            this.mOnDidChangeTreeData.fire(undefined);
        }

        public makeFP(source: SourceItem) {
            source.makeFP();
            // sort the entries again
            source.rule.sortSources()

            this.maybeCacheFP(source);
            this.mOnDidChangeTreeData.fire(undefined);
        }

        public deactivate() {
            // reset highlights
            this.highlightRangePerFile = {};
            // reset children
            this.mData = [];
            this.nameToItem = {};
            this.activeReport = undefined;
            this.reportPath = ".";
            this.mOnDidChangeTreeData.fire(undefined);
        }

        public highlight(editor: vscode.TextEditor, filename: string) {
            if (filename in this.highlightRangePerFile) {
                const range = this.highlightRangePerFile[filename];
                editor.setDecorations(this.decoration, range);
            }
        }

        // this is called when we click an item
        public itemClicked(item: FlowItem) {
            // gather all the flow in the current report to highlight
            // skip reparsing the highlights if the report stayed the same
            if (item.report !== this.activeReport) {
                this.activeReport = item.report;
                this.highlightRangePerFile = {};
                const addedHighlights = new Set<string>();
                for (const flow of item.report.children) {
                    const fullPath = path.join(this.reportPath, flow.file);
                    if (!(fullPath in this.highlightRangePerFile)) {
                        this.highlightRangePerFile[fullPath] = [];
                    }
                    const pos = new vscode.Position(flow.line - 1, 0);
                    const entry = `${fullPath}:${flow.line}`;
                    if (!addedHighlights.has(entry)) {
                        this.highlightRangePerFile[fullPath].push(new vscode.Range(pos, pos));
                        addedHighlights.add(entry);
                    }
                }
            }

            const fullPath = path.join(this.reportPath, item.file);
            // set cursor on the specific flow
            vscode.workspace.openTextDocument(fullPath).then( document => {
                // after opening the document, we set the cursor
                vscode.window.showTextDocument(document).then( editor => {
                        const pos = new vscode.Position(item.line - 1, 0);
                        editor.selection = new vscode.Selection(pos, pos);
                        editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
                        this.highlight(editor, fullPath);
                    }
                );
            });
        }

        public refresh() {
            this.mData = [];
            this.nameToItem = {};
            const editor = vscode.window.activeTextEditor;
            const options: vscode.OpenDialogOptions = {
                canSelectMany: false,
                openLabel: 'Open Report File',
                filters: {
                   'report': ['yaml'],
               }
           };

           // open a file picker if no file is opened
            if (editor === undefined) {
                vscode.window.showOpenDialog(options).then(fileUri => {
                    if (fileUri && fileUri[0]) {
                        const fileName = fileUri[0].fsPath;
                        this.reportPath = path.dirname(fileName);
                        this.reportFile = fileName;
                        this.parseReportFile(fileName);
                        this.mOnDidChangeTreeData.fire(undefined);
                    }
                });
                return;
            }

            const fileName = editor.document.fileName;
            const baseFileName = path.basename(fileName);
            // open a file picker if no yaml file is opened
            if (!baseFileName.includes('.yaml')) {
                vscode.window.showOpenDialog(options).then(fileUri => {
                    if (fileUri && fileUri[0]) {
                        const fileName = fileUri[0].fsPath;
                        this.reportPath = path.dirname(fileName);
                        this.reportFile = fileName;
                        this.parseReportFile(fileName);
                        this.mOnDidChangeTreeData.fire(undefined);
                    }
                });
                return;
            }

            this.reportPath = path.dirname(fileName);
            this.reportFile = fileName;
            this.parseReportFile(fileName);
            this.mOnDidChangeTreeData.fire(undefined);
        }

        public clearInactive() {
            this.inactiveSources = new Set<string>();
            this.fpSources = new Set<string>();
            const workspaceState: vscode.Memento = this.context.workspaceState;
            workspaceState.update(INACTIVE_SOURCES_KEY, undefined);
            workspaceState.update(FP_SOURCES_KEY, undefined);
            vscode.window.showInformationMessage("Cleared Demoted Cache");
            if (this.reportFile) {
                this.mData = [];
                this.nameToItem = {};
                this.parseReportFile(this.reportFile);
                this.mOnDidChangeTreeData.fire(undefined);
            }
        }

        public showInactive() {
            const workspaceState: vscode.Memento = this.context.workspaceState;
            const savedInactive = workspaceState.get(INACTIVE_SOURCES_KEY);
            if (Array.isArray(savedInactive)) {
                vscode.window.showInformationMessage(`Demoted Cache:\n ${savedInactive.map((saved) => "<"+saved+">").join("\n")}`);
            } else {
                vscode.window.showInformationMessage(`Demoted Cache:\n ${savedInactive}`);
            }
        }

        private addFlowToReport(report: ReportItem, flow: Flow) {
            const flowFunc = flow.func;
            const flowFile = flow.file.split(":")[0];
            const flowLine = parseInt(flow.file.split(":")[1]);
            // only add valid lines
            if (flowLine > 0) {
                report.addFlow(new FlowItem(report, flowFunc, flowFile, flowLine));
            }

            if (flow.inlined_at) {
                const inlineFunc = `-> ${flow.func}`;
                const inlineFile = flow.inlined_at.split(":")[0];
                const inlineLine = parseInt(flow.inlined_at.split(":")[1]);
                if (inlineLine > 0) {
                    report.addFlow(new FlowItem(report, inlineFunc, inlineFile, inlineLine));
                }
            }
        }

        public parseReportFile(file: string) {
            try {
                const yamlFile = fs.readFileSync(file, 'utf8');
                const data: Reports = yaml.load(yamlFile) as Reports;

                for (const yamlReport of data.reports) {
                    let ruleItem;
                    let sourceItem;
                    if (yamlReport.rule in this.nameToItem) {
                        ruleItem = this.nameToItem[yamlReport.rule];
                    } else {
                        ruleItem = new RuleItem(yamlReport.rule);
                        this.mData.push(ruleItem);
                        this.nameToItem[yamlReport.rule] = ruleItem;
                    }
                    if (yamlReport.source.file in ruleItem.nameToSource) {
                        sourceItem = ruleItem.nameToSource[yamlReport.source.file];
                    } else {
                        sourceItem = new SourceItem(yamlReport.source.file, ruleItem);
                        ruleItem.addSource(sourceItem);
                        ruleItem.nameToSource[yamlReport.source.file] = sourceItem;
                    }

                    let report = new ReportItem(ruleItem, sourceItem, yamlReport);

                    if (!flowsEqual(yamlReport.source, yamlReport.flow[0])) {
                        this.addFlowToReport(report, yamlReport.source);

                    }

                    if (!yamlReport.sink) {
                        continue;
                    }

                    for (const yamlFlow of yamlReport.flow) {
                        this.addFlowToReport(report, yamlFlow);
                    }

                    const lastFlow = yamlReport.flow[yamlReport.flow.length - 1];
                    if (!flowsEqual(yamlReport.sink, lastFlow)) {
                        this.addFlowToReport(report, yamlReport.sink);
                    }

                    sourceItem.addReport(report);

                    // if the report is marked as inactive, then make it inactive
                    if (yamlReport.type == 'inactive') {
                        this.maybeCacheInactive(report.source);
                    }
                    if (yamlReport.type == 'FP') {
                        this.maybeCacheFP(report.source);
                    }
                }
                // sort all the reports alphabetically
                for (const rule of this.mData) {
                    for (const sourceItem of rule.children) {
                        // deactivate source if we cached it
                        const sourceString = sourceItem.toString();
                        if (this.inactiveSources.has(sourceString)) {
                            sourceItem.deactivate();
                        }
                        if (this.fpSources.has(sourceString)) {
                            sourceItem.makeFP();
                        }
                    }

                    rule.sortSources();
                }

                // sort rules alphabetically
                this.mData.sort((a, b) => (a.rule > b.rule ? 1 : -1));
            } catch (error) {
                vscode.window.showErrorMessage("Invalid Report File: " + error);
            }
        }

        public export() {
            const rules: Object[] = [];
            for (const rule of this.mData) {
               for (const source of rule.children) {
                   for (const report of source.children) {
                        rules.push(report.export())
                   }
               }
            }

            const options: vscode.SaveDialogOptions = {
                saveLabel: 'Export Analysis',
                filters: {
                    'report': ['yaml'],
                }
            };
            vscode.window.showSaveDialog(options).then(fileUri => {
                if (fileUri) {
                    const fileName = fileUri.fsPath;
                    console.log(fileName);

                    if (fileUri) {
                        const yamlStr = yaml.dump({'reports': rules});
                        fs.writeFileSync(fileName, yamlStr);
                    }
                }
            });
        }
    }
}
