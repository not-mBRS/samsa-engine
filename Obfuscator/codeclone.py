import shutil
import keystone as ks #    assembler
import capstone as cs # disassembler
import r2pipe
from capstone import x86_const
import random
import os
mutables = ['nop', 'mov', 'or', 'xor', 'sub', 'add', 'cmp', 'test', 'shl', 'lea', 'not']
illegal_regs = ['al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh', 'cs', 'dr0', 'dr4', 'cr6', 'cr1','cr2','cr3','cr4','cr5','dr1','dr2','dr3','dr5','dr6','dr7','cr0']
class CloneEngine():
    def __init__(self) -> None:
        self.ks = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        self.cs = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.cs.detail = True

def find_mut(meta, ins_analyzed, debug=False):
    new_inst=None
    for i in meta.cs.disasm(bytes.fromhex(ins_analyzed['bytes']), 0x0):
        if i.mnemonic == 'mov':
                if (i.operands[0].type == x86_const.X86_OP_REG and 
                    i.operands[1].type == x86_const.X86_OP_IMM and 
                    i.operands[1].imm == 0):
                    reg1 = i.op_str.split(", ")[0]
                    new_inst = 'xor {}, {};'.format(reg1, reg1).encode()
                # mov reg, 0 -> xor reg, reg / xor reg, 0 / and reg, 0
                elif (i.operands[0].type == x86_const.X86_OP_REG and 
                    i.operands[1].type == x86_const.X86_OP_REG and 
                    i.operands[0].reg != i.operands[1].reg):
                    regs = i.op_str.split(", ")
                    if regs[0] in illegal_regs or regs[1] in illegal_regs:
                        break
                    new_inst = 'push {}; pop {};'.format(regs[1], regs[0]).encode()
                # mov reg, reg2 -> push reg; pop reg2
                elif (i.operands[0].type == x86_const.X86_OP_REG and 
                    i.operands[1].type == x86_const.X86_OP_REG and 
                    i.operands[0].reg == i.operands[1].reg):
                    new_inst = 'nop;'.encode()
            # mov reg, reg -> nop
        #elif ins_analyzed['type'] == 'nop':
            # nop -> nop
        elif i.mnemonic == 'or':
            if ((i.operands[0].type == x86_const.X86_OP_MEM or i.operands[0].type == x86_const.X86_OP_MEM ) and 
                i.operands[1].type == x86_const.X86_OP_IMM and 
                i.operands[1].imm == 0):            
            # or mem/reg, 0 -> nop
                new_inst = 'nop;'.encode()
            elif (i.operands[0].type == x86_const.X86_OP_REG and 
                i.operands[1].type == x86_const.X86_OP_REG and 
                i.operands[0].reg == i.operands[1].reg):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'test {}, {};'.format(reg1, reg1).encode()
            # or reg, reg -> test reg, reg
        elif i.mnemonic == 'xor':
            if ((i.operands[0].type == x86_const.X86_OP_MEM or i.operands[0].type == x86_const.X86_OP_MEM ) and 
                i.operands[1].type == x86_const.X86_OP_IMM and 
                i.operands[1].imm == -1):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'not {};'.format(reg1).encode()
            # xor reg/mem, -1 -> not reg/mem
            elif (i.operands[0].type == x86_const.X86_OP_REG and 
                i.operands[1].type == x86_const.X86_OP_IMM and 
                i.operands[1].imm == 0):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'xor {}, {};'.format(reg1, reg1).encode()
            # xor reg, 0 -> xor reg, reg 
            elif (i.operands[0].type == x86_const.X86_OP_REG and 
                i.operands[1].type == x86_const.X86_OP_REG and 
                i.operands[0].reg == i.operands[1].reg):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'sub {}, {};'.format(reg1, reg1).encode()
            # xor reg, reg -> sub reg, reg
        elif i.mnemonic == 'sub':
            if (i.operands[0].type == x86_const.X86_OP_REG and 
                i.operands[1].type == x86_const.X86_OP_REG and 
                i.operands[0].reg == i.operands[1].reg):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'xor {}, {};'.format(reg1, reg1).encode()
            # sub reg, reg -> xor reg, reg
            elif ((i.operands[0].type == x86_const.X86_OP_MEM or i.operands[0].type == x86_const.X86_OP_REG ) and 
                i.operands[1].type == x86_const.X86_OP_IMM):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'add {}, {};'.format(reg1, "-"+str(i.operands[1].imm)).replace('--','').encode() # I'm ashemed of myself
            # sub reg/mem, imm -> add reg/mem, -imm
        elif i.mnemonic == 'add':
            if ((i.operands[0].type == x86_const.X86_OP_MEM or i.operands[0].type == x86_const.X86_OP_REG ) and 
                i.operands[1].type == x86_const.X86_OP_IMM):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'sub {}, {};'.format(reg1, "-"+str(i.operands[1].imm)).replace('--','').encode() # I'm ashemed of myself
            # add reg/mem, imm -> sub reg, -imm
            elif (i.operands[0].type == x86_const.X86_OP_REG and 
                i.operands[1].type == x86_const.X86_OP_REG and 
                i.operands[0].reg == i.operands[1].reg):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'shl {}, 1;'.format(reg1).encode()
            # add reg, reg -> shl reg, 1
        if i.mnemonic == 'cmp':
            if (i.operands[0].type == x86_const.X86_OP_REG and 
                i.operands[1].type == x86_const.X86_OP_IMM and 
                i.operands[1].imm == 0):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'test {}, {};'.format(reg1, reg1).encode()
            # cmp reg, 0 -> test reg reg / and reg, reg / or reg, reg
        elif i.mnemonic == 'test':
            if (i.operands[0].type == x86_const.X86_OP_REG and 
                i.operands[1].type == x86_const.X86_OP_REG and 
                i.operands[0].reg == i.operands[1].reg):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'or {}, {};'.format(reg1, reg1).encode()
            # test reg, reg -> or reg, reg
        elif i.mnemonic == 'shl':
            if (i.operands[0].type == x86_const.X86_OP_REG and 
                i.operands[1].type == x86_const.X86_OP_IMM and 
                i.operands[1].imm == 1):
                reg1 = i.op_str.split(", ")[0]
                new_inst = 'add {}, {};'.format(reg1, reg1).encode()
            # shl reg, 1 -> add reg, reg
        #elif ins_analyzed['type'] == 'lea':
            # lea reg, [imm] -> add mov, imm
            # lea reg, [reg+imm] -> add reg, imm (fino a 127)
            # lea reg, [reg2] -> add reg, reg2
    if debug and new_inst is not None:
        print(ins_analyzed['opcode'], " -> ", new_inst)
    return new_inst



def mutate_function(meta, func):
    n_ins = len(func['ops'])
    counter = 0
    list_mutations = []

    while counter < n_ins:
        ins_analyzed = func['ops'][counter]

        if ins_analyzed['type'] in mutables:
            mut = find_mut(meta, ins_analyzed)
            if mut is not None:
                try:
                    asm, _ = meta.ks.asm(mut)
                except:
                    breakpoint()
                bytesArr = ''.join(['{:02x}'.format(ins) for ins in asm])
                list_mutations.append(
                    {'offset': ins_analyzed['offset'],
                     'bytes': bytesArr})
        counter+=1
        
    return list_mutations

def patch_executable(r2, mutations):
    for idx, mutation in enumerate(mutations):
        r2.cmd(f"wx {mutation['bytes']} @{mutation['offset']}")

def metamorph_file(input, output):
    shutil.copyfile(input, output)
    r2 = r2pipe.open(output, ['-w'])

    exe_info = r2.cmdj('ij')
    if 'bin' in exe_info:
        if exe_info['bin']['arch'] == 'x86':
            bits = exe_info['bin']['bits']
            r2.cmd('aaa')

    meta = CloneEngine()

    if r2 is not None:
        functions = r2.cmdj('aflj')

        if functions is not None:
            mutations = []
            for fun in functions:
                if fun['type'] == 'fcn':
                    try:
                        fun_code = r2.cmdj(f"pdfj @{fun['name']}")
                    except:  # noqa
                        print("brr")
                    else:
                        mutation = mutate_function(meta, fun_code)
                        if mutation is not None and mutation:
                            mutations.append(mutation)

            mutations = [offsbytes for sub_list in mutations for offsbytes in sub_list]
            patch_executable(r2, mutations)

        r2.quit()

input_folder="./Datasets/Binaries/test"
output_folder="./Datasets/Binaries/Malware_clone"

def main():
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    for root, _, files in os.walk(input_folder):
        for file_name in files:
            input_file = os.path.join(root, file_name)
            family_folder = output_folder+"/"+root.split('/')[-1]
            if not os.path.exists(family_folder):
                os.makedirs(family_folder)
            output_file = os.path.join(family_folder, file_name)
            if os.path.exists(output_file):
                continue
            metamorph_file(input_file, output_file)

if __name__ == "__main__":
    main()


