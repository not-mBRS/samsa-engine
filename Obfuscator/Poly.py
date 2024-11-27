import os
import pefile
import csv
import random
import keystone as ks
import capstone as cs
import r2pipe
import shutil


examples = [
    "mov eax, 0;",
    "mov eax, eax;",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",

]


def __get_functions(self):
    from capstone import x86_const
    inf_margin = self.base_of_code
    sup_margin = self.base_of_code + self.code_size
    index = self.original_entry_point
    func_table = []
    function_calls = set()
    function_calls.add(index)
    processed_functions = []
    processed_addrs = []
    while len(function_calls) > 0:
        addr = function_calls.pop()
        processed_functions.append(addr)
        function = []
        func_table.append(function)
        inst = self.locate_by_original_address(addr)
        jmp_table = set()   # this is the core
        # processed_jumps = []
        cont = True
        while cont:
            function.append(inst)
            processed_addrs.append(inst.original_addr)
            if x86_const.X86_GRP_JUMP in inst.original_inst.groups:
                if inst.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                    jump_address = inst.original_inst.operands[0].imm
                    if inf_margin <= jump_address < sup_margin:
                        if x86_const.X86_INS_JMP == inst.original_inst.id:
                            if jump_address not in processed_addrs:
                                inst.new_bytes = str(bytearray([0x90]))
                                inst = self.locate_by_original_address(jump_address)
                            else:
                                cont = (len(jmp_table) > 0)
                                if cont:
                                    jump_address = jmp_table.pop()
                                    inst = self.locate_by_original_address(jump_address)
                        else:
                            if jump_address not in jmp_table \
                                    and jump_address not in processed_addrs:
                                jmp_table.add(jump_address)
                            cont = (inst.next_instruction is not None)
                            inst = inst.next_instruction
                else:
                    cont = (len(jmp_table) > 0)
                    if cont:
                        jump_address = jmp_table.pop()
                        inst = self.locate_by_original_address(jump_address)
            elif x86_const.X86_GRP_CALL in inst.original_inst.groups \
                    and inst.original_inst.operands[0].type == x86_const.X86_OP_IMM:
                call_address = inst.original_inst.operands[0].imm
                if inf_margin <= call_address < sup_margin \
                        and call_address not in processed_addrs:
                    function_calls.add(call_address)
                cont = (inst.next_instruction is not None)
                inst = inst.next_instruction
            elif x86_const.X86_GRP_RET in inst.original_inst.groups:
                cont = (len(jmp_table) > 0)
                if cont:
                    jump_address = jmp_table.pop()
                    inst = self.locate_by_original_address(jump_address)
            else:
                cont = (inst.next_instruction is not None)
                inst = inst.next_instruction
    return func_table
















''''''
NOP_INSTRUCTIONS = [
    "ADD EAX, 0;",
    "ADD EBX, 0;",
    "ADD ECX, 0;",
    "SUB EAX, 0;",
    "SUB EBX, 0;",
    "SUB ECX, 0;",
    "IMUL EAX, EAX, 1;",
    "IMUL EBX, EBX, 1;",
    "IMUL ECX, ECX, 1;",
    "LEA EAX, [EAX+0];",
    "LEA EBX, [EBX+0];",
    "LEA ECX, [ECX+0];",
    "AND EAX, EAX;",
    "AND EBX, EBX;",
    "AND ECX, ECX;",
    "OR EAX, EAX;",
    "OR EBX, EBX;",
    "OR ECX, ECX;",
    "FNOP;",
    "NOP;",
    "MOV EAX, EAX;",
    "MOV EBX, EBX;",
    "MOV ECX, ECX;",
    "XCHG EAX, EAX;",
    "XCHG EBX, EBX;",
    "XCHG ECX, ECX;",
    "PUSH EAX; POP EAX;",
    "PUSH EBX; POP EBX;",
    "PUSH ECX; POP ECX;",
    "PUSHAD; POPAD;",
    "PUSHFD; POPFD;"
]
NOP_INSTRUCTIONS_DICT = {}

for x in NOP_INSTRUCTIONS:
    keys = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    encoding, count = keys.asm(x)
    NOP_INSTRUCTIONS_DICT[x]=(count, encoding)



def process_executables(input_folder, outptut_folder):
    for root, _, files in os.walk(input_folder):
        for file_name in files:
            breakpoint()
            input_file = os.path.join(root, file_name)
            family_folder = output_folder+"/"+root.split('/')[-1]
            if not os.path.exists(family_folder):
                os.makedirs(family_folder)
            output_file = os.path.join(family_folder, file_name)
            if os.path.exists(output_file):
                continue
            shutil.copyfile(input_file, output_file)
            
            r2 = r2pipe.open(output_file, ['-w'])
            exe_info = r2.cmdj('ij')
            if 'bin' in exe_info:
                if exe_info['bin']['arch'] == 'x86':
                    bits = exe_info['bin']['bits']
                    #morph(r2, bits, output_file)

input_folder = "./datasets/Prove/malware_prova"     
output_folder = "./datasets/Prove/malware_mut"    

def main():
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        process_executables(input_folder, output_folder)

if __name__ == "__main__":
    main()

