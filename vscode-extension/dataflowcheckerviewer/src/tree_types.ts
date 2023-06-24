/* eslint-disable @typescript-eslint/naming-convention */
type Flow = {
	func: string;
	file: string;
	inlined_at: string;
};

function flowsEqual(flow1: Flow, flow2: Flow): boolean {
    return flow1.func === flow2.func &&
           flow1.file === flow2.file &&
           flow1.inlined_at === flow2.inlined_at;
}

type Report = {
	rule: string;
	type: string;
	source: Flow;
	sink:   Flow;
	flow: Array<Flow>;
};

type Reports = {
	reports: Array<Report>;
};

export { Reports, Report, Flow, flowsEqual };
