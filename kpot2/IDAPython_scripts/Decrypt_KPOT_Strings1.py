#Kpot stealer - https://www.virustotal.com/gui/file/67f8302a2fd28d15f62d6d20d748bfe350334e5353cbdef112bd1f8231b5599d/detection

import idautils
import idc

struct_start = 0x401288

def decryptor(index,call_addr):
   decrypted_string="" 
   current_struct_start =  struct_start + 8*index
   current_struct_bytes = idc.get_bytes(current_struct_start, 8)
   print(current_struct_bytes.hex())
   #structure parsing and xoring
   key = int.from_bytes(current_struct_bytes[0:1], byteorder='little', signed=False)
   length = int.from_bytes(current_struct_bytes[2:4], byteorder='little', signed=False)
   buffer_string_addr = int.from_bytes(current_struct_bytes[4:8], byteorder='little', signed=False)
   print(hex(key),hex(length),hex(buffer_string_addr))
   #decrypting
   for i in range(0,length):
    decrypted_string += chr(key ^ idc.get_wide_byte(buffer_string_addr+i)) 
   print(decrypted_string)
   #commenting assembly view
   idc.set_cmt(call_addr, decrypted_string,0)
   #commenting decompile view on the same address as assembly view
   cfunc = idaapi.decompile(call_addr)
   tl = idaapi.treeloc_t()
   tl.ea = call_addr
   tl.itp = idaapi.ITP_SEMI
   cfunc.set_user_cmt(tl, decrypted_string)
   cfunc.save_user_cmts()

#string decrypting func NAME = "String_Decrypt1" - 0040C8F5
string_decrypt_addr = idc.get_name_ea_simple("String_Decrypt1")
print("Func String_Decrypt1 address: 0x%x" % (string_decrypt_addr))
Xref_decrypt_funcs = []
for addr in idautils.CodeRefsTo(string_decrypt_addr, 0):
    Xref_decrypt_funcs.append(addr)
   
print("XREF String_Decrypt1 func COUNT: %d" % (len(Xref_decrypt_funcs)))

for addr in Xref_decrypt_funcs:
    prev_instr = idc.prev_head(addr)
    print("XREF Func String_Decrypt1 prev instruction: 0x%x   %s" % (prev_instr,idc.generate_disasm_line(prev_instr, 0)))
    m = idc.print_insn_mnem(prev_instr)
    #searching instruction in prev-inst addr and finding index argument
    if m == 'mov':
        op = idc.get_operand_type(prev_instr, 1)
        if op == o_imm:
            index = idc.get_operand_value(prev_instr, 1)
            print("Index value: 0x%x" % (index))
            decryptor(index,addr)
            
    if m == 'pop':
        prev_instr2 = idc.prev_head(prev_instr)
        prev_instr3 = idc.prev_head(prev_instr2)
        op = idc.get_operand_type(prev_instr3, 0)
        if op == o_imm:
            index = idc.get_operand_value(prev_instr3, 0)
            print("Index value: 0x%x" % (index))
            decryptor(index,addr)
            
    if m == 'xor':
        index = 0
        print("Index value: 0x%x" % (index))
        decryptor(index,addr)
        
    if m == 'inc':
        index = 1
        print("Index value: 0x%x" % (index))
        decryptor(index,addr)

    if m == 'lea':
        prev_instr2 = idc.prev_head(prev_instr)
        m2 = idc.print_insn_mnem(prev_instr2)
        if m2 == 'mov':
            index = 0x67
            print("Index value: 0x%x" % (index))
            decryptor(index,addr)
        else:
            index = 0x93
            print("Index value: 0x%x" % (index))
            decryptor(index,addr)



