#!/usr/bin/env python3
from glob import glob
import json
import pandas as pd
from scipy import stats
from collections import OrderedDict
import argparse

def parse_syzkaller_bench_file(file):
    with open(file, 'r') as f:
        data = list(f.read())
        closing_indices = []
        for i, c in enumerate(data):
            if c == '}':
                closing_indices.append(i)
        closing_indices.pop()
        for closing_idx in reversed(closing_indices):
            data.insert(closing_idx+1, ',')
        data.insert(0, '[')
        data.append(']')
        s = "".join(data)
        return json.loads(s)

def stats_after_seconds(syzkaller_bench, time):
    for b in syzkaller_bench:
        if b['fuzzing'] >= time:
            return b
    raise Exception("not found!")

def gen_table(data):
    df = pd.DataFrame(data=data)

    transp = df.T.reset_index()
    columns = [col for col in transp.columns if col != 'benchmark' and col != 'index']
    df = transp.groupby('benchmark')[columns].median().T
    df = df.loc[(df != 0).all(axis=1), :]

    df['uncontained overhead'] = df['uncontained']/df['baseline']
    df['kasan overhead'] = df['kasan']/df['baseline']

    pd.options.display.float_format = '{:.2f}'.format
    print(df)


def start(prefix=''):
    results = {}
    for f in glob(f"{prefix}*"):
        r = parse_syzkaller_bench_file(f)

        obj_after = stats_after_seconds(r, 60 * 60)
        benchmark = 'unknown'

        if f[len(prefix):].startswith("baseline"):
            benchmark = 'baseline'
        elif f[len(prefix):].startswith("uncontained"):
            benchmark = 'uncontained'
        elif f[len(prefix):].startswith("kasan"):
            benchmark = 'kasan'
        key = f[len(prefix):]
        obj_after['benchmark'] = benchmark

        results[key] = obj_after

    results = OrderedDict(sorted(results.items()))
    gen_table(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='parse lmbench results and compute results')
    parser.add_argument('--prefix', dest='prefix', default='', type=str)
    args = parser.parse_args()

    start(prefix=args.prefix)
