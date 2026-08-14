#!/usr/bin/env python3
import json
import sys
import os
import re

def parse_addr(s):
    """Extract hex address from string if possible; return None if not."""
    # If string contains '::', take part after last '::'
    if '::' in s:
        s = s.split('::')[-1]
    # Remove any non-hex characters (like leading underscores)
    s = re.sub(r'[^0-9a-fA-F]', '', s)
    if not s:
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None

def find_function_by_addr(functions, addr_str):
    addr_int = parse_addr(addr_str)
    if addr_int is None:
        return None
    for f in functions:
        start = parse_addr(f["start"])
        end = parse_addr(f["end"])
        if start is None or end is None:
            continue
        if start <= addr_int <= end:
            return f
    return None

def build_callers_map(callgraph):
    callers = {}
    for caller, info in callgraph.items():
        for callee in info.get("calls", []):
            callers.setdefault(callee, []).append(caller)
    return callers

def build_call_tree(callgraph, callers, target_func, depth=0, max_depth=5):
    tree = {"function": target_func, "callers": []}
    if depth >= max_depth:
        return tree
    for caller in callers.get(target_func, []):
        tree["callers"].append(build_call_tree(callgraph, callers, caller, depth+1, max_depth))
    return tree

def analyze(ghidra_dir, output_dir="string_usage_output"):
    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(ghidra_dir, "functions_deep.json")) as f:
        functions = json.load(f)
    with open(os.path.join(ghidra_dir, "strings_xrefs.json")) as f:
        strings = json.load(f)
    with open(os.path.join(ghidra_dir, "callgraph.json")) as f:
        callgraph = json.load(f)

    callers_map = build_callers_map(callgraph)

    result = []
    for s in strings:
        entry = {
            "string": s["string"],
            "address": s["address"],
            "refs": []
        }
        for ref in s["refs"]:
            ref_addr = ref["from"]
            func = find_function_by_addr(functions, ref_addr)
            ref_info = {
                "from": ref_addr,
                "type": ref.get("type", ""),
                "function": func["name"] if func else None
            }
            # اگر آدرس معتبر نیست و تابعی پیدا نشد، فقط اگر آدرس قابل تجزیه باشه اضافه می‌کنیم
            # در غیر این صورت می‌توانیم ردش کنیم
            if func is not None or parse_addr(ref_addr) is not None:
                entry["refs"].append(ref_info)
        result.append(entry)

    with open(os.path.join(output_dir, "string_usage.json"), "w") as f:
        json.dump(result, f, indent=2)

    target_addr = os.environ.get("TARGET_ADDR")
    if target_addr:
        func = find_function_by_addr(functions, target_addr)
        if func:
            tree = build_call_tree(callgraph, callers_map, func["name"])
            with open(os.path.join(output_dir, "target_call_tree.json"), "w") as f:
                json.dump(tree, f, indent=2)

    print("String usage analysis completed. Output in '{}'".format(output_dir))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python find_string_usage.py <ghidra_output_dir> [output_dir]")
        sys.exit(1)
    ghidra_dir = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "string_usage_output"
    analyze(ghidra_dir, out_dir)
