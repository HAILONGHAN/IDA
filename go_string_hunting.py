# Currently it's normally ebx, but could in theory be anything - seen ebp
VALID_REGS = ['ebx', 'ebp']
# Currently it's normally esp, but could in theory be anything - seen eax
VALID_DEST = ['esp', 'eax', 'ecx', 'edx']
def is_string_load(addr):
    patterns = []
    # Check for first part
    if GetMnem(addr) == 'mov':
        # Could be unk_ or asc_, ignored ones could be loc_ or inside []
        if GetOpnd(addr, 0) in VALID_REGS and not ('[' in GetOpnd(addr, 1) or 'loc_' in GetOpnd(addr, 1)) and('offset ' in GetOpnd(addr, 1) or 'h' in GetOpnd(addr, 1)):
            from_reg = GetOpnd(addr, 0)
            # Check for second part
            addr_2 = FindCode(addr, SEARCH_DOWN)
            try:
                dest_reg = GetOpnd(addr_2, 0)[GetOpnd(addr_2, 0).index('[') + 1:GetOpnd(addr_2, 0).index('[') + 4]
            except ValueError:
                return False
            if GetMnem(addr_2) == 'mov' and dest_reg in VALID_DEST and ('[%s' % dest_reg) in GetOpnd(addr_2, 0) and GetOpnd(addr_2, 1) == from_reg:
                # Check for last part, could be improved
                addr_3 = FindCode(addr_2, SEARCH_DOWN)
                if GetMnem(addr_3) == 'mov' and (('[%s+' % dest_reg) in GetOpnd(addr_3, 0) or GetOpnd(addr_3, 0) in VALID_DEST) and 'offset ' not in GetOpnd(addr_3, 1) and 'dword ptr ds' not in GetOpnd(addr_3, 1):
                    try:
                        dumb_int_test = GetOperandValue(addr_3, 1)
                        if dumb_int_test > 0 and dumb_int_test < sys.maxsize:
                            return True
                    except ValueError:
                        return False
def create_string(addr, string_len):
    debug('Found string load @ 0x%x with length of %d' % (addr, string_len))
    # This may be overly aggressive if we found the wrong area...
    if GetStringType(addr) is not None and GetString(addr) is not None and len(GetString(addr)) != string_len:
        debug('It appears that there is already a string present @ 0x%x' % addr)
        MakeUnknown(addr, string_len, DOUNK_SIMPLE)
    if GetString(addr) is None and MakeStr(addr, addr + string_len):
        return True
    else:
        # If something is already partially analyzed (incorrectly) we need to MakeUnknown it
        MakeUnknown(addr, string_len, DOUNK_SIMPLE)
        if MakeStr(addr, addr + string_len):
            return True
        debug('Unable to make a string @ 0x%x with length of %d' % (addr, string_len))
    return False