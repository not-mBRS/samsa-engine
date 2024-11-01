import lief
import copy
import random
import keystone as ks

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

def find_target_section(pe):
    for section in pe.sections:
        if '.text' in section.name:
            return section.size
    raise ValueError("No suitable section found for modification")

def get_content(size):
    keys = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    nops=[]
    while size > 0:
        encoding, count = keys.asm(random.choice(NOP_INSTRUCTIONS))
        if count > size :
            continue
        if size == 1:
            encoding = 0
            count = 1 
        size-=count
        nops+=encoding
        print(size)
    content = bytearray(nops)
    return content
    
def inject_sections(input_path, output_path, section_data, section_names, scaling_factors):
    with open(input_path, 'rb') as file:
        binary_data = file.read()
    modified_binary = copy.deepcopy(binary_data)
    pe_binary = lief.PE.parse(list(modified_binary))
    
    how_many_bytes = find_target_section(pe_binary)
    content_to_append = get_content(how_many_bytes) 
    
    section = lief.PE.Section()
    section.name = ".newsec"
    section.content = content_to_append
    
    pe_binary.add_section(section)
       
    builder = lief.PE.Builder(pe_binary)
    builder.build()
    
    with open(output_path, 'wb') as file:
        file.write(bytearray(builder.get_build()))
    
input_path = "./calc.exe"     # Original file path
output_path = "./calc_demetrio.exe"    # Path for the modified file

section_data = [
    bytearray([0x90] * 100),  # Example data for section 1 (NOP instructions, 100 bytes)
]

section_names = ['.newsec1']   # Names for the new sections
scaling_factors = [0.5, 1.0]               # Scaling factors for each section

inject_sections(input_path, output_path, section_data, section_names, scaling_factors)
