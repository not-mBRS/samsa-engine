import os
import pefile
import csv
import random
import keystone as ks
import capstone as cs
import r2pipe
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

def get_slack_space(section_data):
    zero_count = 0
    for byte in reversed(section_data):
        if byte == 0x00:
            zero_count += 1
        else:
            break
    return zero_count

def find_target_section(pe):
    for section in pe.sections:
        if b'.text' in section.Name:
            return section
    raise ValueError("No suitable section found for modification")

def inject_random_nop(pe, bits, output_file, percentage=.9):
    if bits==32:
        mode = ks.KS_MODE_32
    elif bits==64:
        os.remove(output_file)
        #return
        mode = ks.KS_MODE_64
    else:
        print(bits)
    keys = ks.Ks(ks.KS_ARCH_X86, mode)
    try:
        target_section= find_target_section(pe)
    except:
        os.remove(output_file)
        return            
    slack_region_byte_count = get_slack_space(target_section.get_data())
    injection_size = int(slack_region_byte_count * percentage)
    if slack_region_byte_count < 16: 
        os.remove(output_file)
        return
    to_insert = []
    while(injection_size>1):
        random_nop = random.choice(NOP_INSTRUCTIONS)
        encoding, count = keys.asm(random_nop)
        if count>injection_size:
            continue
        to_insert.append(encoding)
        injection_size-=count
    to_insert_flatten = [item for sublist in to_insert for item in sublist]
    first_part = target_section.PointerToRawData + 15 + len(target_section.get_data()) - slack_region_byte_count
    with open(output_file, 'rb') as f:
        original_data = f.read()
    with open(output_file, 'wb') as f:
        modified_data = (
            original_data[:first_part] +
            bytes(to_insert_flatten) +
            original_data[first_part + len(bytes(to_insert_flatten)):] # last part
        )
        
        f.write(modified_data)

def process_executables(input_folder, outptut_folder, percentage=.5):
    for root, _, files in os.walk(input_folder):
        for file_name in files:
            input_file = os.path.join(root, file_name)
            family_folder = output_folder+"/"+str(int(percentage*100))+"/"+root.split('/')[-1]
            if not os.path.exists(family_folder):
                os.makedirs(family_folder)
            output_file = os.path.join(family_folder, file_name)
            #if os.path.exists(output_file):
            #    continue
            shutil.copyfile(input_file, output_file)
            
            r2 = r2pipe.open(output_file, ['-w'])
            exe_info = r2.cmdj('ij')
            if 'bin' in exe_info:
                #if exe_info['bin']['arch'] == 'x86':
                    bits = exe_info['bin']['bits']
                    pe = pefile.PE(output_file)
                    inject_random_nop(pe, bits, output_file, percentage)

input_folder = "./Obfuscator/uno"     
output_folder = "./Obfuscator/due"    
def main():
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    for perc in [0.05, 0.25, 0.5, 0.98]:
        process_executables(input_folder, output_folder, perc)

if __name__ == "__main__":
    main()