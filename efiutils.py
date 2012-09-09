"""
efiutils.py - some utility functions to aid with the reverse engineering of EFI executables.
"""

from idaapi import *
from idautils import *
from idc import *
import re

MAX_STACK_DEPTH = 1
IMAGE_HANDLE_NAME       = 'gImageHandle'
SYSTEM_TABLE_NAME       = 'gSystemTable'
SYSTEM_TABLE_STRUCT     = 'EFI_SYSTEM_TABLE'
BOOT_SERVICES_NAME      = 'gBootServices'
BOOT_SERVICES_STRUCT    = 'EFI_BOOT_SERVICES'
RUNTIME_SERVICES_NAME   = 'gRuntimeServices'
RUNTIME_SERVICES_STRUCT = 'EFI_RUNTIME_SERVICES'


def go():
    rename_tables()
    update_structs()


def rename_tables():
    """
    Look at the entry point function and find where the SystemTable parameter is stored, along with the
    RuntimeServices and BootServices tables. Rename the globals these are stored in.

    The entry point for an EFI executable is called like this:
    EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE * SystemTable)

    ImageHandle is passed in rcx, SystemTable is passed in rdx.
    """
    regs = {}
    regs['im'] = ['rcx']
    regs['st'] = ['rdx']
    regs['bs'] = []
    regs['rs'] = []

    entry = GetEntryOrdinal(0)

    rename_tables_internal(entry, regs)


def rename_tables_internal(function, regs, stackdepth=0):
    names = {'im': IMAGE_HANDLE_NAME, 'st': SYSTEM_TABLE_NAME, 'bs': BOOT_SERVICES_NAME, 'rs': RUNTIME_SERVICES_NAME}

    print "Processing function at " + str(function)
 
    for item in FuncItems(function):
        #print "regs = " + str(regs)
        # Bail out if we hit a call
        if GetMnem(item) == "call":
            if stackdepth == MAX_STACK_DEPTH:
                print "  - Hit stack depth limit, bailing!"
                return
            else:
                if GetOpType(item, 0) in [o_imm, o_far, o_near]:
                    rename_tables_internal(LocByName(GetOpnd(item, 0)), regs, stackdepth+1)
                else:
                    print "  - Can't follow call, bailing!"
                    return

        if GetMnem(item) in ["mov", "lea"]:
            # Rename data
            for key in names:
                if GetOpnd(item, 1) in regs[key] and GetOpType(item, 0) == o_mem:
                    print "  - Found a copy to a memory address for %s, updating: %s" % (names[key], GetDisasm(item))
                    MakeName(LocByName(GetOpnd(item, 0).split(":")[-1]), names[key])
                    break

            # Eliminate overwritten registers
            for key in names:
                if GetOpnd(item, 0) in regs[key] and GetOpnd(item, 1) not in regs[key]:
                    print "  - Untracking register %s for %s: %s" % (GetOpnd(item, 0), names[key], GetDisasm(item))
                    regs[key].remove(GetOpnd(item, 0))

            # Keep track of registers containing the EFI tables etc
            if GetOpnd(item, 1) in regs['im'] and GetOpType(item, 0) == o_reg and GetOpnd(item, 0) not in regs['im']:
                # A tracked register was copied to a new register, track the new one
                print "  - Tracking register %s for image handle: %s" % (GetOpnd(item, 0), GetDisasm(item))
                regs['im'].append(GetOpnd(item, 0))
            if GetOpnd(item, 1) in regs['st'] and GetOpType(item, 0) == o_reg and GetOpnd(item, 0) not in regs['st']:
                # A tracked register was copied to a new register, track the new one
                print "  - Tracking register %s for system table: %s" % (GetOpnd(item, 0), GetDisasm(item))
                regs['st'].append(GetOpnd(item, 0))
            if GetOpType(item, 1) == o_displ and reg_from_displ(GetOpnd(item, 1)) in regs['st']:
                # A tracked register was used in a right operand with a displacement
                offset = GetOperandValue(item, 1)
                if offset == 0x60:
                    print "  - Tracking register %s for boot services table: %s" % (GetOpnd(item, 0), GetDisasm(item))
                    regs['bs'].append(GetOpnd(item, 0))
                elif offset == 0x58:
                    print "  - Tracking register %s for runtime services table: %s" % (GetOpnd(item, 0), GetDisasm(item))
                    regs['rs'].append(GetOpnd(item, 0))
                OpStroffEx(item, 1, GetStrucIdByName(SYSTEM_TABLE_STRUCT), 0)


def update_structs():
    """Update xrefs to the major EFI tables to be struct offsets."""
    structs = {SYSTEM_TABLE_NAME: SYSTEM_TABLE_STRUCT, BOOT_SERVICES_NAME: BOOT_SERVICES_STRUCT,
               RUNTIME_SERVICES_NAME: RUNTIME_SERVICES_STRUCT}
    for key in structs:
        addr = LocByName(key);
        if addr == BADADDR:
            print "Couldn't find address for " + key
        else:
            print "Updating structure references for %s (%s)" % (key, structs[key])
            update_struct_offsets(addr, structs[key])


def update_struct_offsets(data_addr, struct_name):
    """
    Find xrefs to a struct pointer and change all the offsets to be struct offsets. This is useful for updating
    references to function pointers in EFI tables.

    For example:
    mov     rax, cs:gBootServices
    call    qword ptr [rax+150h]

    Becomes:
    mov     rax, cs:gBootServices
    call    [rax+EFI_BOOT_SERVICES.UninstallMultipleProtocolInterfaces]

    Parameters:
    addr        - The address of the struct pointer global
    struct_name - The name of the structure to use for offsets
    """

    # Find all xrefs to this data in the code
    xrefs = list(DataRefsTo(data_addr))
    print "Found %d xrefs" % len(xrefs)

    # Process xrefs
    for xref in xrefs:
        # We're only interested in xrefs in code where the left operand is a register, and the right operand is the
        # memory address of our data structure.
        if GetOpType(xref, 0) == o_reg and GetOpType(xref, 1) == o_mem or GetOperandValue(xref, 1) == struct_name:
            print "Processing xref from %d: %s" % (xref, GetDisasm(xref))
            update_struct_offsets_for_xref(xref, struct_name)
        else:
            print "Too hard basket - xref from %d: %s" % (xref, GetDisasm(xref))


def update_struct_offsets_for_xref(xref, struct_name):
    regs = {}
    regs['hndl'] = []
    regs['ptr'] = []

    # Are we looking at a handle or a pointer?
    if GetMnem(xref) == "mov":
        regs['ptr'].append(GetOpnd(xref, 0))
    elif GetMnem(xref) == "lea":
        regs['hndl'].append(GetOpnd(xref, 0))

    # Get the rest of the instructions in this function
    items = list(FuncItems(xref))
    if len(items):
        idx = items.index(xref)+1
        items = items[idx:]
    else:
        print "  - Xref %d wasn't marked as a function" % xref
        cur = xref
        while True:
            if not isCode(cur) or GetMnem(cur) in ['call', 'jmp']:
                break
            items.append(cur)
            cur = NextAddr(cur)

    # Iterate through the rest of the instructions in this function looking for tracked registers with a displacement
    for item in items:
        # Update any call instruction with a displacement from our register
        for op in range(0, 2):
            if GetOpType(item, op) == o_displ and reg_from_displ(GetOpnd(item, op)) in regs['ptr']:
                print "  - Updating operand %d in instruction: %s" % (op, GetDisasm(item))
                OpStroffEx(item, op, GetStrucIdByName(struct_name), 0)

        # If we find a mov instruction that dereferences a handle, track the destination register
        for reg in regs['hndl']:
            if GetOpnd(item, 1) == "[%s]" % reg and GetMnem(item) == 'mov' and GetOpnd(item, 0) not in regs:
                print "  - Found a dereference, tracking register %s" % GetOpnd(item, 0)
                regs['mov'].append(GetOpnd(item, 0))

        # If we've found an instruction that overwrites a tracked register, stop tracking it
        if GetMnem(item) in ["mov", "lea", "xor"] and GetOpType(item, 0) == o_reg:
            if GetOpnd(item, 0) in regs['ptr']:
                print "  - Untracking pointer register %s: " % GetOpnd(item, 0) + GetDisasm(item)
                regs['ptr'].remove(GetOpnd(item, 0))
            elif GetOpnd(item, 0) in regs['hndl']:
                print "  - Untracking handle register %s: " % GetOpnd(item, 0) + GetDisasm(item)
                regs['hndl'].remove(GetOpnd(item, 0))

        # If we hit a call, just bail
        if GetMnem(item) == "call":
            break

        # If we're not tracking any registers, bail
        if len(regs['ptr']) == 0 and len(regs['hndl']) == 0:
            break


def reg_from_displ(displ):
    """
    Return the register to which a displacement is relative.

    e.g. qword ptr [rbx+8] -> rbx
    """
    m = re.match(r'.*\[(.*)[\+\-]', displ)
    return m.group(1)
