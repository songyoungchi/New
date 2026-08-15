# -*- coding: utf-8 -*-
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import Reference
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.address import AddressSet
import json
import os
import errno

def make_dir(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

def int_to_little_endian_hex(value, byte_len=4):
    """Convert integer to little-endian byte string for search."""
    bytes_list = []
    for i in range(byte_len):
        bytes_list.append((value >> (8 * i)) & 0xff)
    return bytes_list

def find_pointer_refs(program, addr):
    """Find all occurrences of the given address as a 4-byte little-endian value in memory."""
    memory = program.getMemory()
    search_bytes = int_to_little_endian_hex(addr.getOffset(), 4)
    byte_str = bytes(search_bytes)
    results = []
    # جستجوی ساده در تمام بلوک‌های حافظه
    for block in memory.getBlocks():
        start = block.getStart()
        end = block.getEnd()
        try:
            data = bytearray()
            current = start
            while current <= end:
                data.append(memory.getByte(current) & 0xff)
                current = current.add(1)
        except MemoryAccessException:
            continue
        # جستجو در data
        import re
        for m in re.finditer(re.escape(byte_str), data):
            offset = m.start()
            ptr_addr = start.add(offset)
            results.append(ptr_addr)
    return results

def dump_disassembly(program, listing, addr, instructions_before=10, instructions_after=10):
    """Dump disassembly around the given address."""
    code = []
    current = addr
    # go backward
    for _ in range(instructions_before):
        prev = listing.getInstructionBefore(current)
        if prev is None:
            break
        code.append(str(prev))
        current = prev.getAddress()
    code.reverse()
    # forward
    current = addr
    ins = listing.getInstructionAt(current)
    if ins:
        code.append(str(ins))
        for _ in range(instructions_after):
            next_ins = listing.getInstructionAfter(current)
            if next_ins is None:
                break
            code.append(str(next_ins))
            current = next_ins.getAddress()
    return "\n".join(code)

# --- main ---
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
functions = func_manager.getFunctions(True)

for func in functions:
    # (همان کد قبلی برای دیکامپایل، pcode و ...)
    # برای جلوگیری از طولانی شدن، این بخش رو خلاصه می‌کنم
    name = func.getName()
    entry = func.getEntryPoint()
    func_output_dir = os.path.join(output_dir, name)
    make_dir(func_output_dir)
    # ... (کد کامل قبلی)
    functions_data.append({
        "name": name,
        "address": str(entry),
        # ... سایر فیلدها
    })

# --- Strings deep trace ---
strings_deep = []
data_iterator = listing.getDefinedData(True)
for data in data_iterator:
    if data.hasStringValue():
        addr = data.getAddress()
        value = data.getValue()
        direct_refs = []
        for ref in ref_manager.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            containing_func = func_manager.getFunctionContaining(from_addr)
            func_name = containing_func.getName() if containing_func else None
            direct_refs.append({
                "from": str(from_addr),
                "type": str(ref.getReferenceType()),
                "function": func_name,
                "disassembly": dump_disassembly(program, listing, from_addr, 5, 5)
            })
        # Pointer refs
        ptr_refs = []
        ptr_locations = find_pointer_refs(program, addr)
        for ptr_addr in ptr_locations:
            # xrefs to this pointer location
            for ref in ref_manager.getReferencesTo(ptr_addr):
                from_addr = ref.getFromAddress()
                containing_func = func_manager.getFunctionContaining(from_addr)
                func_name = containing_func.getName() if containing_func else None
                ptr_refs.append({
                    "pointer_addr": str(ptr_addr),
                    "from": str(from_addr),
                    "type": str(ref.getReferenceType()),
                    "function": func_name,
                    "disassembly": dump_disassembly(program, listing, from_addr, 5, 5)
                })
        strings_deep.append({
            "string": value,
            "address": str(addr),
            "direct_refs": direct_refs,
            "pointer_refs": ptr_refs
        })

with open(os.path.join(output_dir, "string_deep_trace.json"), "w") as f:
    json.dump(strings_deep, f, indent=2)

print("Deep string trace saved to string_deep_trace.json")
