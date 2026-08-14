#!/usr/bin/env python3
import angr
import json
import os
import sys
import re
import networkx as nx

def analyze(binary_path):
    output_dir = "angr_output"
    os.makedirs(output_dir, exist_ok=True)

    proj = angr.Project(binary_path, auto_load_libs=False)

    # ساخت CFG با حل indirect jumps و ارجاعات متقابل
    cfg = proj.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        data_references=True,
        cross_references=True,
        force_complete_scan=False
    )

    # ---------- اطلاعات توابع ----------
    functions_info = []
    for func_addr, func in cfg.kb.functions.items():
        func_info = {
            "addr": hex(func_addr),
            "name": func.name,
            "blocks": [hex(b.addr) for b in func.blocks],
            "call_sites": []
        }
        for block in func.blocks:
            for ins in block.capstone.insns:
                if ins.insn.mnemonic in ("bl", "blx"):
                    target = ins.insn.operands[0].imm if ins.insn.operands[0].type == 1 else None
                    if target:
                        func_info["call_sites"].append({
                            "from": hex(ins.address),
                            "to": hex(target) if target in cfg.kb.functions else "external"
                        })
                    else:
                        func_info["call_sites"].append({
                            "from": hex(ins.address),
                            "to": "indirect"
                        })
        functions_info.append(func_info)

    with open(os.path.join(output_dir, "functions.json"), "w") as f:
        json.dump(functions_info, f, indent=2)

    # ---------- Callgraph ----------
    callgraph = nx.DiGraph()
    for func_addr, func in cfg.kb.functions.items():
        callgraph.add_node(func.name)
        for block in func.blocks:
            for ins in block.capstone.insns:
                if ins.insn.mnemonic in ("bl", "blx"):
                    target = ins.insn.operands[0].imm if ins.insn.operands[0].type == 1 else None
                    if target and target in cfg.kb.functions:
                        callgraph.add_edge(func.name, cfg.kb.functions[target].name)

    nx.write_adjlist(callgraph, os.path.join(output_dir, "callgraph_adjlist.txt"))
    nx.write_gml(callgraph, os.path.join(output_dir, "callgraph.gml"))

    # ---------- رشته‌ها و ارجاعات ----------
    strings_found = []
    # الگوهای مورد جستجو (می‌تونی اضافه کنی)
    patterns = [b"login", b"Something went wrong", b"error", b"failed", b"success", b"key", b"secret"]
    for pattern in patterns:
        addrs = proj.loader.memory.find(pattern)
        for addr in addrs:
            xrefs = cfg.kb.xrefs.get_xrefs_to(addr)
            strings_found.append({
                "string": pattern.decode(errors="ignore"),
                "address": hex(addr),
                "refs": [{"from": hex(x.ins_addr), "type": str(x.type)} for x in xrefs]
            })

    # علاوه بر الگوها، همه رشته‌های ASCII (حداقل ۴ کاراکتر) را هم استخراج کن
    # می‌توانی از angr.calling_conventions یا روش دستی استفاده کنی؛ اینجا ساده‌تر
    mem = proj.loader.memory
    min_addr = min(proj.loader.main_object.segments, key=lambda s: s.min_addr).min_addr
    max_addr = max(proj.loader.main_object.segments, key=lambda s: s.max_addr).max_addr
    try:
        data = mem.load(min_addr, max_addr - min_addr)
    except Exception:
        data = b''
    if data:
        ascii_re = re.compile(rb'[\x20-\x7e]{4,}')
        for match in ascii_re.finditer(data):
            s = match.group().decode()
            addr = min_addr + match.start()
            xrefs = cfg.kb.xrefs.get_xrefs_to(addr)
            if xrefs:
                strings_found.append({
                    "string": s,
                    "address": hex(addr),
                    "refs": [{"from": hex(x.ins_addr), "type": str(x.type)} for x in xrefs]
                })

    with open(os.path.join(output_dir, "strings_xrefs.json"), "w") as f:
        json.dump(strings_found, f, indent=2)

    print("angr analysis completed. Output saved to '{}'".format(output_dir))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python angr_analysis.py <binary>")
        sys.exit(1)
    analyze(sys.argv[1])
