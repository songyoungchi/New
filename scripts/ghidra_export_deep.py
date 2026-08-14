# -*- coding: utf-8 -*-
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import Reference
import json
import os
import errno

def make_dir(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

output_dir = "ghidra_output"
make_dir(output_dir)

program = getCurrentProgram()
listing = program.getListing()
func_manager = program.getFunctionManager()
ref_manager = program.getReferenceManager()
monitor = ConsoleTaskMonitor()

decomp = DecompInterface()
decomp.openProgram(program)

functions_data = []
functions = func_manager.getFunctions(True)  # true = forward

for func in functions:
    name = func.getName()
    entry = func.getEntryPoint()
    func_output_dir = os.path.join(output_dir, name)
    make_dir(func_output_dir)

    # ---------- Decompilation ----------
    decomp_res = decomp.decompileFunction(func, 60, monitor)
    c_code = ""
    if decomp_res is not None and decomp_res.decompileCompleted():
        c_code = decomp_res.getDecompiledFunction().getC()
        with open(os.path.join(func_output_dir, name + ".c"), "w") as f:
            f.write(c_code)

    # ---------- Pcode ----------
    pcode_ops = []
    instructions = listing.getInstructions(func.getBody(), True)
    for ins in instructions:
        for pcode in ins.getPcode():
            pcode_ops.append({
                "address": str(ins.getAddress()),
                "mnemonic": str(pcode.getMnemonic()),
                "inputs": [str(inp) for inp in pcode.getInputs()],
                "output": str(pcode.getOutput())
            })
    with open(os.path.join(func_output_dir, name + "_pcode.json"), "w") as f:
        json.dump(pcode_ops, f, indent=2)

    # ---------- Xrefs ----------
    refs_to = []
    refs_from = []
    for ref in ref_manager.getReferencesTo(entry):
        refs_to.append({
            "from": str(ref.getFromAddress()),
            "type": str(ref.getReferenceType())
        })
    for ref in ref_manager.getReferencesFrom(entry):
        refs_from.append({
            "to": str(ref.getToAddress()),
            "type": str(ref.getReferenceType())
        })

    # ---------- Stack Variables ----------
    stack_vars = []
    for var in func.getStackFrame().getStackVariables():
        stack_vars.append({
            "name": var.getName(),
            "offset": var.getStackOffset(),
            "size": var.getLength(),
            "data_type": str(var.getDataType())
        })

    # ---------- Function boundaries ----------
    body = func.getBody()
    start_addr = str(body.getMinAddress())
    end_addr = str(body.getMaxAddress())

    functions_data.append({
        "name": name,
        "address": str(entry),
        "start": start_addr,
        "end": end_addr,
        "c_file": os.path.join(name, name + ".c"),
        "pcode_file": os.path.join(name, name + "_pcode.json"),
        "refs_to": refs_to,
        "refs_from": refs_from,
        "stack_vars": stack_vars,
        "signature": str(func.getSignature())
    })

# ---------- Strings and Xrefs ----------
strings_data = []
data_iterator = listing.getDefinedData(True)
for data in data_iterator:
    if data.hasStringValue():
        addr = data.getAddress()
        value = data.getValue()
        refs = []
        for ref in ref_manager.getReferencesTo(addr):
            refs.append({
                "from": str(ref.getFromAddress()),
                "type": str(ref.getReferenceType())
            })
        strings_data.append({
            "string": value,
            "address": str(addr),
            "refs": refs
        })

with open(os.path.join(output_dir, "strings_xrefs.json"), "w") as f:
    json.dump(strings_data, f, indent=2)

# ---------- Callgraph ----------
callgraph = {}
for func in func_manager.getFunctions(True):
    func_name = func.getName()
    callgraph[func_name] = {
        "address": str(func.getEntryPoint()),
        "calls": []
    }
    instructions = listing.getInstructions(func.getBody(), True)
    for ins in instructions:
        refs = ref_manager.getReferencesFrom(ins.getAddress())
        for ref in refs:
            if ref.getReferenceType().isCall():
                target_func = func_manager.getFunctionAt(ref.getToAddress())
                if target_func:
                    callgraph[func_name]["calls"].append(target_func.getName())

with open(os.path.join(output_dir, "callgraph.json"), "w") as f:
    json.dump(callgraph, f, indent=2)

# ---------- Summary ----------
with open(os.path.join(output_dir, "functions_deep.json"), "w") as f:
    json.dump(functions_data, f, indent=2)

print("Ghidra deep analysis completed. Output saved to '{}'".format(output_dir))
