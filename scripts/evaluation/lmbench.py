#!/usr/bin/env python3
from glob import glob
import sys
import pandas as pd
from scipy import stats
from collections import OrderedDict
import argparse

SIMPLE_LAT_SPLIT_INDEX = 0

LMBENCH_DIR = "/var/tmp/lmbench"

simple_lat_benchs = ["Simple syscall", "Simple read", "Simple write", "Simple stat", "Simple fstat",
        "Simple open/close", "Select on 10 fd's", "Select on 100 fd's", "Select on 250 fd's",
        "Select on 500 fd's", "Select on 10 tcp fd's", "Select on 100 tcp fd's",
        "Select on 250 tcp fd's", "Select on 500 tcp fd's", "Signal handler installation",
        "Signal handler overhead", "Pipe latency", "AF_UNIX sock stream latency",
        "Process fork+exit", "Process fork+execve", "Process fork+/bin/sh -c",
        f"Pagefaults on {LMBENCH_DIR}/XXX", "UDP latency using localhost",
        "TCP latency using localhost", "TCP/IP connection cost to localhost"]


def parse_lmbench_simple_lat(lmbench_result):
    result = {}
    for l in lmbench_result.splitlines():
        s = l.split(": ")
        key = s[0]
        if key not in simple_lat_benchs:
            continue
        val = float(s[1].split()[0]) # discard microseconds part
        result[key] = val
    return result


def parse_lmbench_file(f):
    results = {}
    print('f: ', f)
    with open(f, "rb") as fh:
        data = fh.read().decode("utf-8", errors="ignore")
        r = parse_lmbench_simple_lat(data)
        results["lat"] = r
    return results


def gen_table(data):
    lat_data = {k: data[k]["lat"] for k in data}
    df = pd.DataFrame(data=lat_data)

    transp = df.T.reset_index()
    df = transp.groupby('benchmark')[simple_lat_benchs].median().T

    df['uncontained overhead']       = df['uncontained']/df['baseline']
    df['kasan overhead']             = df['kasan']/df['baseline']
    # df['uncontained_kasan overhead'] = df['uncontained_kasan']/df['baseline']
    # df['kasan_no_checks overhead'] = df['kasan_no_checks']/df['baseline']

    df.loc['geomean'] = {
            'baseline': '-',
            'uncontained': '-',
            'kasan': '-',
            # 'uncontained_kasan': '-',
            # 'kasan_no_checks': '-',
            'uncontained overhead': stats.gmean(df['uncontained overhead'].astype(float)),
            'kasan overhead': stats.gmean(df['kasan overhead'].astype(float)),
            # 'uncontained_kasan overhead': stats.gmean(df['uncontained_kasan overhead'].astype(float)),
            # 'kasan_no_checks overhead': stats.gmean(df['kasan_no_checks overhead'].astype(float)),
    }

    pd.options.display.float_format = '{:.2f}'.format
    print(df)


def start(prefix=''):
    results = {}
    for f in glob(f"{prefix}*.*"):
        r = parse_lmbench_file(f)
        benchmark = 'unknown'

        if f[len(prefix):].startswith("baseline."):
            benchmark = 'baseline'
        elif f[len(prefix):].startswith("uncontained."):
            benchmark = 'uncontained'
        elif f[len(prefix):].startswith("kasan."):
            benchmark = 'kasan'
        elif f[len(prefix):].startswith("uncontained_kasan."):
            benchmark = 'uncontained_kasan'
        elif f[len(prefix):].startswith("kasan_no_checks."):
            benchmark = 'kasan_no_checks'
        key = f[len(prefix):]
        r['lat']['benchmark'] = benchmark

        results[key] = r

    results = OrderedDict(sorted(results.items()))
    gen_table(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='parse lmbench results and compute results')
    parser.add_argument('--prefix', dest='prefix', default='', type=str)
    args = parser.parse_args()

    start(prefix=args.prefix)
