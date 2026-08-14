#!/usr/bin/env python3
import json
import os
import sys

def merge(artifacts_dir):
    merged = {
        "ghidra": {},
        "angr": {}
    }

    ghidra_path = os.path.join(artifacts_dir, "ghidra-results")
    angr_path = os.path.join(artifacts_dir, "angr-results")

    if os.path.exists(ghidra_path):
        for fname in ["functions_deep.json", "strings_xrefs.json", "callgraph.json"]:
            fpath = os.path.join(ghidra_path, fname)
            if os.path.exists(fpath):
                with open(fpath) as f:
                    merged["ghidra"][fname] = json.load(f)
        # کپی کردن پوشه‌های توابع (اختیاری)
        functions_dir = os.path.join(ghidra_path)
        # فقط فایل‌های JSON را می‌گیریم

    if os.path.exists(angr_path):
        for fname in ["functions.json", "strings_xrefs.json"]:
            fpath = os.path.join(angr_path, fname)
            if os.path.exists(fpath):
                with open(fpath) as f:
                    merged["angr"][fname] = json.load(f)

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
