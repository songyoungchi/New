#!/usr/bin/env python3
import json
import sys
import os

def analyze(ghidra_dir, output_dir="string_usage_output"):
    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(ghidra_dir, "strings_xrefs.json")) as f:
        strings = json.load(f)

    result = []
    for s in strings:
        entry = {
            "string": s["string"],
            "address": s["address"],
            "refs": []
        }
        for ref in s["refs"]:
            func_name = ref.get("function", None)
            entry["refs"].append({
                "from": ref["from"],
                "type": ref.get("type", ""),
                "function": func_name
            })
        result.append(entry)

    with open(os.path.join(output_dir, "string_usage.json"), "w") as f:
        json.dump(result, f, indent=2)

    print("String usage analysis completed. Output in '{}'".format(output_dir))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python find_string_usage.py <ghidra_output_dir> [output_dir]")
        sys.exit(1)
    ghidra_dir = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "string_usage_output"
    analyze(ghidra_dir, out_dir)
