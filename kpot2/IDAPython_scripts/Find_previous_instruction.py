import idautils

def Find_prev_ins(string_decrypt_func):
    string_decrypt_addr = idc.get_name_ea_simple(string_decrypt_func)
    print("Func %s address: 0x%x" % (string_decrypt_func,string_decrypt_addr))
    Xref_decrypt_funcs = []
    for addr in idautils.CodeRefsTo(string_decrypt_addr, 0):
        Xref_decrypt_funcs.append(addr)
       
    print("XREF %s func COUNT: %d" % (string_decrypt_func,len(Xref_decrypt_funcs)))
    
    for addr in Xref_decrypt_funcs:
        prev_instr = idc.prev_head(addr)
        print("XREF Func %s prev instruction: 0x%x   %s" % (string_decrypt_func,prev_instr,idc.generate_disasm_line(prev_instr, 0)))
       
Find_prev_ins("String_Decrypt1")
Find_prev_ins("String_Decrypt2")