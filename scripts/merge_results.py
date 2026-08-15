#!/usr/bin/env python3
import json
import os
import sys

def merge(artifacts_dir):
    merged = {
        "ghidra": {},
        "angr": {},
        "string_usage": {}
    }

    # مسیرها
    ghidra_path = os.path.join(artifacts_dir, "ghidra-results")
    angr_path = os.path.join(artifacts_dir, "angr-results")
    string_usage_path = os.path.join(artifacts_dir, "string-usage-results")

    # بارگذاری خروجی گیدرا
    if os.path.exists(ghidra_path):
        for fname in ["functions_deep.json", "strings_xrefs.json", "callgraph.json", "string_deep_trace.json"]:
            fpath = os.path.join(ghidra_path, fname)
            if os.path.exists(fpath):
                with open(fpath) as f:
                    merged["ghidra"][fname] = json.load(f)

    # بارگذاری خروجی angr
    if os.path.exists(angr_path):
        for fname in ["functions.json", "strings.json"]:
            fpath = os.path.join(angr_path, fname)
            if os.path.exists(fpath):
                with open(fpath) as f:
                    merged["angr"][fname] = json.load(f)

    # بارگذاری خروجی string_usage
    if os.path.exists(string_usage_path):
        for fname in ["string_usage_full.json", "target_string_usage.json"]:
            fpath = os.path.join(string_usage_path, fname)
            if os.path.exists(fpath):
                with open(fpath) as f:
                    merged["string_usage"][fname] = json.load(f)

    out_dir = "merged_output"
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "analysis_report.json"), "w") as f:
        json.dump(merged, f, indent=2)

    print("Merged results written to {}/analysis_report.json".format(out_dir))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python merge_results.py <artifacts_dir>")
        sys.exit(1)
    merge(sys.argv[1])
