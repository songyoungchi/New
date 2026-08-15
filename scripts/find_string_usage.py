#!/usr/bin/env python3
import json
import os
import sys

def build_callers_map(callgraph):
    """ساخت نقشه callers از callgraph"""
    callers = {}
    for caller, info in callgraph.items():
        for callee in info.get("calls", []):
            callers.setdefault(callee, []).append(caller)
    return callers

def build_call_tree(callgraph, callers, target_func, depth=0, max_depth=5):
    """ساخت درخت callers از یک تابع"""
    tree = {"function": target_func, "callers": []}
    if depth >= max_depth:
        return tree
    for caller in callers.get(target_func, []):
        tree["callers"].append(build_call_tree(callgraph, callers, caller, depth + 1, max_depth))
    return tree

def analyze(ghidra_dir, output_dir="string_usage_output"):
    os.makedirs(output_dir, exist_ok=True)

    # بارگذاری فایل‌ها
    with open(os.path.join(ghidra_dir, "string_deep_trace.json")) as f:
        strings_deep = json.load(f)

    with open(os.path.join(ghidra_dir, "callgraph.json")) as f:
        callgraph = json.load(f)

    callers_map = build_callers_map(callgraph)

    result = []
    for s in strings_deep:
        usage_functions = set()

        # جمع‌آوری نام توابع از ارجاعات مستقیم و اشاره‌گرها
        for ref in s["direct_refs"]:
            if ref["function"]:
                usage_functions.add(ref["function"])
        for ref in s["pointer_refs"]:
            if ref["function"]:
                usage_functions.add(ref["function"])

        # ساخت درخت callers برای هر تابع استفاده‌کننده
        usage_trees = []
        for func_name in usage_functions:
            tree = build_call_tree(callgraph, callers_map, func_name)
            usage_trees.append(tree)

        entry = {
            "string": s["string"],
            "address": s["address"],
            "direct_refs": s["direct_refs"],
            "pointer_refs": s["pointer_refs"],
            "usage_functions": list(usage_functions),
            "call_trees": usage_trees
        }
        result.append(entry)

    with open(os.path.join(output_dir, "string_usage_full.json"), "w") as f:
        json.dump(result, f, indent=2)

    # اگر آدرس هدف مشخص شده باشد، فقط همان رشته را استخراج کن
    target_addr = os.environ.get("TARGET_ADDR")
    if target_addr:
        target = [x for x in result if x["address"].lower() == target_addr.lower()]
        if target:
            with open(os.path.join(output_dir, "target_string_usage.json"), "w") as f:
                json.dump(target[0], f, indent=2)

    print("String usage analysis completed. Output in '{}'".format(output_dir))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python find_string_usage.py <ghidra_output_dir> [output_dir]")
        sys.exit(1)
    ghidra_dir = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "string_usage_output"
    analyze(ghidra_dir, out_dir)
