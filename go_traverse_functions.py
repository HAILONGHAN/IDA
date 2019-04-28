def is_simple_wrapper(addr):
    if GetMnem(addr) == 'xor' and GetOpnd(addr, 0) == 'edx' and  GetOpnd(addr, 1) == 'edx':
        addr = FindCode(addr, SEARCH_DOWN)
        if GetMnem(addr) == 'jmp' and GetOpnd(addr, 0) == 'runtime_morestack':
            return True
    return False
def create_runtime_ms():
    debug('Attempting to find runtime_morestack function for hooking on...')
    text_seg = ida_segment.get_segm_by_name('.text')
    # This code string appears to work for ELF32 and ELF64 AFAIK
    runtime_ms_end = ida_search.find_text(text_seg.startEA, 0, 0, "word ptr ds:1003h, 0", SEARCH_DOWN)
    runtime_ms = ida_funcs.get_func(runtime_ms_end)
    if idc.MakeNameEx(runtime_ms.startEA, "runtime_morestack", SN_PUBLIC):
        debug('Successfully found runtime_morestack')
    else:
        debug('Failed to rename function @ 0x%x to runtime_morestack' % runtime_ms.startEA)
    return runtime_ms
def traverse_xrefs(func):
    func_created = 0
    if func is None:
        return func_created
    # First
    func_xref = ida_xref.get_first_cref_to(func.startEA)
    # Attempt to go through crefs
    while func_xref != 0xffffffffffffffff:
        # See if there is a function already here
        if ida_funcs.get_func(func_xref) is None:
            # Ensure instruction bit looks like a jump
            func_end = FindCode(func_xref, SEARCH_DOWN)
            if GetMnem(func_end) == "jmp":
                # Ensure we're jumping back "up"
                func_start = GetOperandValue(func_end, 0)
                if func_start < func_xref:
                    if idc.MakeFunction(func_start, func_end):
                        func_created += 1
                    else:
                        # If this fails, we should add it to a list of failed functions
                        # Then create small "wrapper" functions and backtrack through the xrefs of this
                        error('Error trying to create a function @ 0x%x - 0x%x' %(func_start, func_end))
        else:
            xref_func = ida_funcs.get_func(func_xref)
            # Simple wrapper is often runtime_morestack_noctxt, sometimes it isn't though...
            if is_simple_wrapper(xref_func.startEA):
                debug('Stepping into a simple wrapper')
                func_created += traverse_xrefs(xref_func)
            if ida_funcs.get_func_name(xref_func.startEA) is not None and 'sub_' not in ida_funcs.get_func_name(xref_func.startEA):
                debug('Function @0x%x already has a name of %s; skipping...' % (func_xref, ida_funcs.get_func_name(xref_func.startEA)))
            else:
                debug('Function @ 0x%x already has a name %s' % (xref_func.startEA, ida_funcs.get_func_name(xref_func.startEA)))
        func_xref = ida_xref.get_next_cref_to(func.startEA, func_xref)
    return func_created
def find_func_by_name(name):
    text_seg = ida_segment.get_segm_by_name('.text')
    for addr in Functions(text_seg.startEA, text_seg.endEA):
        if name == ida_funcs.get_func_name(addr):
            return ida_funcs.get_func(addr)
    return None
def runtime_init():
    func_created = 0
    if find_func_by_name('runtime_morestack') is not None:
        func_created += traverse_xrefs(find_func_by_name('runtime_morestack'))
        func_created += traverse_xrefs(find_func_by_name('runtime_morestack_noctxt'))
    else:
        runtime_ms = create_runtime_ms()
        func_created = traverse_xrefs(runtime_ms)
    return func_created