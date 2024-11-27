import lief
import copy
import random
import keystone as ks
import os
import shutil

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

def find_target_section(pe):
    for section in pe.sections:
        if '.text' in section.name:
            return section.size
    raise ValueError("No suitable section found for modification")

def get_content(size, keys):
    nops=[]
    while size > 0:
        mnemonic, count_encoding = random.choice(list(NOP_INSTRUCTIONS_DICT.items()))
        count, encoding = count_encoding
        if size == 1:
            nops+=[0]
            return bytearray(nops)
        if count > size :
            continue
        size-=len(bytearray(encoding))
        nops+=encoding
    return bytearray(nops)
    
def inject_sections(input_folder, output_folder, keys):
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
            pe_binary = lief.PE.parse(list(modified_binary))
            if pe_binary is None:
                continue
            how_many_bytes = find_target_section(pe_binary)
            content_to_append = get_content(how_many_bytes-16, keys) 
            
            section = lief.PE.Section()
            
            section.name = ".data4"
            #xor_key = os.urandom(16)
            #key_length = len(xor_key)
            content_encrypted = content_to_append#bytearray(content_to_append[i] ^ xor_key[i % key_length] for i in range(len(content_to_append)))
            section.content = content_encrypted
            
            section.characteristics = pe_binary.get_section(".text").characteristics   
            pe_binary.add_section(section)
            
            pe_binary.optional_header.sizeof_code *= 2
            
            builder = lief.PE.Builder(pe_binary)
            builder.build()
            
            with open(output_file, 'wb') as file:
                file.write(bytearray(builder.get_build()))
    
input_folder = "./prova"     
output_folder = "./prova"    


def main():
    keys = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    inject_sections(input_folder, output_folder, keys)

if __name__ == "__main__":
    main()