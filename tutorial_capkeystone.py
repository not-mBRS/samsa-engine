import keystone as ks
import capstone as cs


lCode_test=[]
CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
#CODE = b"\x55\x48\xa1\xb8\x13\x00\x00"

print("-- Test capstone --")

md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32) # select the architecture (change CS_MODE_32 to CS_MODE_64 for 64bit mode)
for i in md.disasm(CODE, 0x0): # disassemble the code. 0x0 is the offset for the address. The output is a list of statements
    print("0x%x:\t%s\t%s\t%s" %(i.address, i.mnemonic, i.op_str, i.bytes)) # i is the statement. address, mnemonic, op_str and bytes all return strings
    lCode_test.append(i.mnemonic+" "+i.op_str)
#code_test='; '.join(lCode_test)
#print(ode_test)
print("-- Test keystone --")

code = b'ADD EAX, 0; SUB EAX, 0; IMUL EAX, EAX, 1; LEA EAX, [EAX + 0]; OR EAX, EAX; AND EAX, EAX; FNOP; MOV EAX, EAX; XCHG EAX, EAX'
try:
    keys = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32) # same as with capstone
    encoding, count = keys.asm(code) # assembles the code. returns a list of the encoded bytes
    print("[ ", end='')
    for i in encoding:
        print("%02x " %i, end='')
    print("]")
    
except ks.KsError as e:
    print("ERROR: %s" %e)