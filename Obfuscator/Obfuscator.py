import random
import os
import shutil
import pefile
import lief
import r2pipe
import keystone as ks #    assembler
import capstone as cs # disassembler
from capstone import x86_const
import copy
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

MARGIN = 16

class Obfuscator:
    def __init__(self, exec, dbg=True):
        self.ks = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        self.cs = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.cs.detail = True
        self.dbg=dbg

        self.exec_lief=lief.PE.parse(list(exec))
        
    def injection(self, percentage):
        target_section = None

        for section in self.exec_lief.sections:
            if '.text' in section.name:
                target_section =  section
        slack_region_byte_count = target_section.padding

        injection_size = int(slack_region_byte_count * percentage)
        #if slack_region_byte_count < 16: 
        #    os.remove(output_file)
        #    return
        to_insert = []
        while(injection_size>1):
            random_nop = random.choice(NOP_INSTRUCTIONS)
            encoding, count = keys.asm(random_nop)
            if count>injection_size:
                continue
            to_insert.append(encoding)
            injection_size-=count
        to_insert_flatten = [item for sublist in to_insert for item in sublist]
        first_part = target_section.pointerto_raw_data + 15
        modified_data = (
                #original_data[:first_part] +
                #bytes(to_insert_flatten) +
                #original_data[first_part + len(bytes(to_insert_flatten)):] # last part
            )          

    def addition(self):
        size_text=0
        for section in self.exec_lief.sections:
            if '.text' in section.name:
                size_text = section.size
                break
        nops=[]
        while size_text > 0:
            mnemonic, count_encoding = random.choice(list(NOP_INSTRUCTIONS_DICT.items()))
            count, encoding = count_encoding
            if size_text == 1:
                nops+=[0]
                content_to_append = bytearray(nops)
                break
            if count > size_text :
                continue
            size_text-=len(bytearray(encoding))
            nops+=encoding
        content_to_append=bytearray(nops)
        
        section = lief.PE.Section()
            
        section.name = ".data4"
        #xor_key = os.urandom(16)
        #key_length = len(xor_key)
        content_encrypted = content_to_append#bytearray(content_to_append[i] ^ xor_key[i % key_length] for i in range(len(content_to_append)))
        section.content = content_encrypted

        section.characteristics = self.exec_lief.get_section(".text").characteristics   
        self.exec_lief.add_section(section)
        self.exec_lief.optional_header.sizeof_code *= 2
        self.exec_lief=lief.PE.parse(lief.PE.Builder(self.exec_lief).build().get_build())

    def clone(self):
        pass

    def metadata(self):
        pass

output_folder="./due"
input_folder="./uno"

def main():
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    for root, _, files in os.walk(input_folder):
        for file_name in files:
            print("Working on "+file_name)
            input_file = os.path.join(root, file_name)
            family_folder = output_folder+"/"+root.split('/')[-1]
            if not os.path.exists(family_folder):
                os.makedirs(family_folder)
            output_file = os.path.join(family_folder, file_name)
            if os.path.exists(output_file):
                continue
            shutil.copyfile(input_file, output_file)
            with open(input_file, 'rb') as file:
                binary_data = file.read()
            modified_binary = copy.deepcopy(binary_data)
            
            pe_binary = Obfuscator(modified_binary)
            #pe_binary.addition()
            pe_binary.injection(0.5)


if __name__ == "__main__":
    main()