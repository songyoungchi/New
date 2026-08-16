# -*- coding: utf-8 -*-
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import Reference
from ghidra.program.model.mem import MemoryAccessException
import json
import os
import errno

def make_dir(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

def int_to_le_bytes(value, n=4):
    """تبدیل عدد به آرایه بایتی little-endian با طول n بایت"""
    b = []
    for i in range(n):
        b.append((value >> (8 * i)) & 0xff)
    return b

def find_pattern_in_memory(program, pattern, align_mask=None):
    """جستجوی الگوی بایتی با استفاده از findBytes (سریع‌تر)"""
    memory = program.getMemory()
    results = []
    # تبدیل pattern به رشته‌ی بایتی
    pattern_bytes = bytes(pattern)
    # جستجو در همه بلاک‌ها
    for block in memory.getBlocks():
        start = block.getStart()
        end = block.getEnd()
        try:
            # استفاده از findBytes در Ghidra
            found = memory.findBytes(start, end, pattern_bytes, None, True, monitor)
            while found is not None:
                addr = found
                # اگر align_mask داده شده، بیت‌های موردنظر را ماسک کن
                if align_mask is not None:
                    addr = addr.getNewAddress(addr.getOffset() & ~align_mask)
                results.append(addr)
                # جستجوی بعدی
                next_start = found.add(1)
                if next_start.compareTo(end) > 0:
                    break
                found = memory.findBytes(next_start, end, pattern_bytes, None, True, monitor)
        except Exception as e:
            continue
    return results

def dump_disassembly(listing, addr, before=5, after=5):
    """استخراج دیس‌اسمبل اطراف یک آدرس"""
    lines = []
    current = addr
    for _ in range(before):
        prev = listing.getInstructionBefore(current)
        if prev is None:
            break
        lines.append(str(prev))
        current = prev.getAddress()
    lines.reverse()

    current = addr
    ins = listing.getInstructionAt(current)
    if ins is not None:
        lines.append(str(ins))
        for _ in range(after):
            next_ins = listing.getInstructionAfter(current)
            if next_ins is None:
                break
            lines.append(str(next_ins))
            current = next_ins.getAddress()
    return "\n".join(lines)

# ---------- تنظیمات اولیه ----------
output_dir = "ghidra_output"
make_dir(output_dir)

program = getCurrentProgram()
listing = program.getListing()
func_manager = program.getFunctionManager()
ref_manager = program.getReferenceManager()
memory = program.getMemory()
monitor = ConsoleTaskMonitor()

decomp = DecompInterface()
decomp.openProgram(program)

# ---------- تحلیل توابع ----------
functions_data = []
functions = func_manager.getFunctions(True)

for func in functions:
    name = func.getName()
    entry = func.getEntryPoint()
    func_output_dir = os.path.join(output_dir, name)
    make_dir(func_output_dir)

    # دیکامپایل
    c_code = ""
    decomp_res = decomp.decompileFunction(func, 60, monitor)
    if decomp_res is not None and decomp_res.decompileCompleted():
        c_code = decomp_res.getDecompiledFunction().getC()
        with open(os.path.join(func_output_dir, name + ".c"), "w") as f:
            f.write(c_code)

    # Pcode
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

    # Xrefs مستقیم به تابع
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

    # Stack Variables
    stack_vars = []
    for var in func.getStackFrame().getStackVariables():
        stack_vars.append({
            "name": var.getName(),
            "offset": var.getStackOffset(),
            "size": var.getLength(),
            "data_type": str(var.getDataType())
        })

    # محدوده تابع
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

# ---------- تحلیل رشته‌ها ----------
strings_xrefs = []
strings_deep = []

data_iterator = listing.getDefinedData(True)
ptr_size = program.getDefaultPointerSize()  # اندازه اشاره‌گر (معمولاً 4 برای ARM32)

for data in data_iterator:
    if not data.hasStringValue():
        continue

    str_addr = data.getAddress()
    str_value = str(data.getValue()) if data.getValue() else ""

    # ۱) ارجاعات مستقیم
    direct_refs = []
    for ref in ref_manager.getReferencesTo(str_addr):
        from_addr = ref.getFromAddress()
        # برای Thumb بیت ۰ را حذف کن
        normalized_addr = from_addr.getNewAddress(from_addr.getOffset() & ~1)
        func = func_manager.getFunctionContaining(normalized_addr)
        func_name = func.getName() if func else None
        direct_refs.append({
            "from": str(from_addr),
            "type": str(ref.getReferenceType()),
            "function": func_name,
            "disassembly": dump_disassembly(listing, from_addr, 5, 5)
        })

    # ۲) ارجاعات اشاره‌گر (Little-Endian با اندازه ptr_size)
    ptr_locations = find_pattern_in_memory(
        program,
        int_to_le_bytes(str_addr.getOffset(), ptr_size),
        align_mask=1  # نادیده گرفتن بیت ۰ برای Thumb
    )
    pointer_refs = []
    for ptr_addr in ptr_locations:
        # نرمال‌سازی آدرس اشاره‌گر
        normalized_ptr = ptr_addr.getNewAddress(ptr_addr.getOffset() & ~1)
        # xrefs به خود مکان اشاره‌گر
        for ref in ref_manager.getReferencesTo(ptr_addr):
            from_addr = ref.getFromAddress()
            func = func_manager.getFunctionContaining(from_addr.getNewAddress(from_addr.getOffset() & ~1))
            func_name = func.getName() if func else None
            pointer_refs.append({
                "pointer_addr": str(ptr_addr),
                "from": str(from_addr),
                "type": str(ref.getReferenceType()),
                "function": func_name,
                "disassembly": dump_disassembly(listing, from_addr, 5, 5)
            })
        if not pointer_refs:
            # اگر xref نبود، فقط دیس‌اسمبل اطراف اشاره‌گر را بده
            pointer_refs.append({
                "pointer_addr": str(ptr_addr),
                "from": None,
                "type": "pointer",
                "function": None,
                "disassembly": dump_disassembly(listing, ptr_addr, 5, 5)
            })

    strings_xrefs.append({
        "string": str_value,
        "address": str(str_addr),
        "direct_refs": direct_refs
    })

    strings_deep.append({
        "string": str_value,
        "address": str(str_addr),
        "direct_refs": direct_refs,
        "pointer_refs": pointer_refs
    })

with open(os.path.join(output_dir, "strings_xrefs.json"), "w") as f:
    json.dump(strings_xrefs, f, indent=2)

with open(os.path.join(output_dir, "string_deep_trace.json"), "w") as f:
    json.dump(strings_deep, f, indent=2)

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
