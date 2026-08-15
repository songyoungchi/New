#!/usr/bin/env python3
import angr
import json
import os
import sys
import re
import networkx as nx

def get_xrefs_to(xrefs, addr):
    """
    استخراج ارجاعات به یک آدرس.
    سازگار با networkx graph و XRefManager قدیمی.
    """
    refs = []
    addr_int = addr if isinstance(addr, int) else int(addr, 16)

    if hasattr(xrefs, 'in_edges'):
        # angr جدید: گراف networkx
        for src, dst, data in xrefs.in_edges(addr_int, data=True):
            refs.append({
                "from": hex(src),
                "type": str(data.get("type", "unknown"))
            })
    else:
        try:
            for x in xrefs.get_xrefs_to(addr_int):
                refs.append({
                    "from": hex(x.ins_addr),
                    "type": str(x.type)
                })
        except AttributeError:
            pass
    return refs

def analyze(binary_path):
    output_dir = "angr_output"
    os.makedirs(output_dir, exist_ok=True)

    proj = angr.Project(binary_path, auto_load_libs=False)

    print("[*] Building CFG...")
    cfg = proj.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        data_references=True,
        cross_references=True,
        force_complete_scan=False
    )

    # ---------- اطلاعات توابع ----------
    print("[*] Extracting function info...")
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
                    target = None
                    if ins.insn.operands[0].type == 1:  # immediate
                        target = ins.insn.operands[0].imm
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
    print("[+] functions.json saved")

    # ---------- Callgraph ----------
    print("[*] Building callgraph...")
    callgraph = nx.DiGraph()
    for func_addr, func in cfg.kb.functions.items():
        callgraph.add_node(func.name)
        for block in func.blocks:
            for ins in block.capstone.insns:
                if ins.insn.mnemonic in ("bl", "blx"):
                    target = None
                    if ins.insn.operands[0].type == 1:
                        target = ins.insn.operands[0].imm
                    if target and target in cfg.kb.functions:
                        callgraph.add_edge(func.name, cfg.kb.functions[target].name)

    nx.write_adjlist(callgraph, os.path.join(output_dir, "callgraph_adjlist.txt"))
    nx.write_gml(callgraph, os.path.join(output_dir, "callgraph.gml"))
    print("[+] callgraph saved")

    # ---------- رشته‌ها ----------
    print("[*] Extracting strings and xrefs...")
    strings_found = []

    # الگوهای مورد جستجو
    patterns = [
        b"login", b"Something went wrong", b"error", b"failed",
        b"success", b"key", b"secret", b"password", b"username",
        b"internet", b"network", b"http", b"https"
    ]
    for pattern in patterns:
        addrs = proj.loader.memory.find(pattern)
        for addr in addrs:
            xrefs = get_xrefs_to(cfg.kb.xrefs, addr)
            strings_found.append({
                "string": pattern.decode(errors="ignore"),
                "address": hex(addr),
                "refs": xrefs
            })

    # استخراج تمام رشته‌های ASCII (حداقل ۴ کاراکتر)
    min_addr = None
    max_addr = None
    try:
        segments = proj.loader.main_object.segments
        min_addr = min(segments, key=lambda s: s.min_addr).min_addr
        max_addr = max(segments, key=lambda s: s.max_addr).max_addr
    except Exception:
        pass

    if min_addr is not None and max_addr is not None:
        try:
            data = proj.loader.memory.load(min_addr, max_addr - min_addr)
        except Exception:
            data = b''
        if data:
            ascii_re = re.compile(rb'[\x20-\x7e]{4,}')
            for match in ascii_re.finditer(data):
                s = match.group().decode()
                addr = min_addr + match.start()
                # جلوگیری از تکرار
                if not any(x["address"] == hex(addr) for x in strings_found):
                    xrefs = get_xrefs_to(cfg.kb.xrefs, addr)
                    strings_found.append({
                        "string": s,
                        "address": hex(addr),
                        "refs": xrefs
                    })

    with open(os.path.join(output_dir, "strings.json"), "w") as f:
        json.dump(strings_found, f, indent=2)
    print("[+] strings.json saved ({} strings)".format(len(strings_found)))

    print("[*] angr analysis completed. Output saved to '{}'".format(output_dir))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python angr_analysis.py <binary>")
        sys.exit(1)
    analyze(sys.argv[1])
