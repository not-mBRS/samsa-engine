import random
import os
import shutil
import lief
import r2pipe 
import keystone as ks #    assembler
import capstone as cs # disassembler
from capstone import x86_const
import copy
import argparse
import string

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

MARGIN_PADDING = 16

def generate_random_string():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=5))

class Obfuscator:
    def __init__(self, output_file, dbg=True):
        self.ks = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        self.cs = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.mutables = ['nop', 'mov', 'or', 'xor', 'sub', 'add', 'cmp', 'test', 'shl', 'lea', 'not']
        self.illegal_regs = ['al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh', 'cs', 'dr0', 'dr4', 'cr6', 'cr1','cr2','cr3','cr4','cr5','dr1','dr2','dr3','dr5','dr6','dr7','cr0']
        self.cs.detail = True
        self.dbg=dbg
        self.path_file=output_file
        with open(output_file, 'rb') as file:
            binary_data = file.read()
        self.exec_lief=lief.PE.parse(list(copy.deepcopy(binary_data)))

    def read_file(self, name):
        with open(name, 'rb') as file:
            binary_data = file.read()
        self.exec_lief=lief.PE.parse(list(binary_data))

    def write(self, name=""):
        builder = lief.PE.Builder(self.exec_lief)
        builder.build()
        builder.write(self.path_file+"_"+name)

    def injection(self, percentage):
        target_section = None

        for section in self.exec_lief.sections:
            if '.text' in section.name:
                target_section =  section
        slack_region_byte_count = len(target_section.padding)

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

        exe_build = lief.PE.Builder(self.exec_lief)
        exe_build.build()
        original_data=bytearray(exe_build.get_build())
        to_insert_flatten = [item for sublist in to_insert for item in sublist]
        first_part = target_section.pointerto_raw_data + 15 + target_section.sizeof_raw_data - slack_region_byte_count
        with open(self.path_file+"_final", 'wb') as f:
            modified_data = (
                    original_data[:first_part] +
                    bytes(to_insert_flatten) +
                    original_data[first_part + len(bytes(to_insert_flatten)):] # last part
                )          
            f.write(modified_data)
        #self.read_file(self.path_file+"_injection")
        #self.write("")

    def addition(self, perc):
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
        #exe_build = lief.PE.Builder(self.exec_lief)
        #exe_build.build()
        #self.exec_lief=lief.PE.parse(list(bytearray(exe_build.get_build())))
        self.write("addition")


    def find_mut(self, ins_analyzed):
        new_inst=None
        for i in self.cs.disasm(bytes.fromhex(ins_analyzed['bytes']), 0x0):
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
                        if regs[0] in self.illegal_regs or regs[1] in self.illegal_regs:
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
        return new_inst
        
    def mutate_function(self, func):
        n_ins = len(func['ops'])
        counter = 0
        list_mutations = []

        while counter < n_ins:
            ins_analyzed = func['ops'][counter]

            if ins_analyzed['type'] in self.mutables:
                mut = self.find_mut(ins_analyzed)                                                   
                if mut is not None:
                    try:
                        asm, _ = self.ks.asm(mut)
                    except:
                        breakpoint()
                    bytesArr = ''.join(['{:02x}'.format(ins) for ins in asm])
                    list_mutations.append(
                        {'offset': ins_analyzed['offset'],
                        'bytes': bytesArr})
            counter+=1
        
        return list_mutations
    
    def patch_executable(self, r2, mutations):
        for idx, mutation in enumerate(mutations):
            r2.cmd(f"wx {mutation['bytes']} @{mutation['offset']}")

    def clone(self):
        r2 = r2pipe.open(self.path_file+"_addition", ['-w'])
        exe_info = r2.cmdj('ij')
        if 'bin' in exe_info:
            if exe_info['bin']['arch'] == 'x86':
                bits = exe_info['bin']['bits']
                r2.cmd('aaa')
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
                            mutation = self.mutate_function(fun_code)
                            if mutation is not None and mutation:
                                mutations.append(mutation)

                mutations = [offsbytes for sub_list in mutations for offsbytes in sub_list]
                self.patch_executable(r2, mutations)
            with open(self.path_file+"_addition", 'rb') as file:
                binary_data = file.read()
            self.exec_lief=lief.PE.parse(list(binary_data))
            r2.quit()
            self.write("clone")

    def metadata(self):
        # + imported libraries
        # + overlay
        try:
            self.exec_lief.header.time_date_stamps = random.randint(0, 0xFF)
        except:
            return 0
        self.exec_lief.optional_header.minor_image_version = random.randint(0, 0xFF)
        self.exec_lief.optional_header.major_image_version = random.randint(0, 0xFF)
        self.exec_lief.optional_header.minor_linker_version = random.randint(0, 0xFF)
        self.exec_lief.optional_header.major_linker_version = random.randint(0, 0xFF)
        self.exec_lief.optional_header.minor_operating_system_version = random.randint(0, 0xFF)
        self.exec_lief.optional_header.major_operating_system_version = random.randint(0, 0xFF)
        self.exec_lief.optional_header.minor_subsystem_version = random.randint(0, 0xFF)
        self.exec_lief.optional_header.major_subsystem_version = random.randint(0, 0xFF)
        added_libs=[]
        for _ in range(random.randint(0, 10)):
            added_libs.append(generate_random_string()+".dll")
            self.exec_lief.add_library(added_libs[-1])
            for _ in range(random.randint(0, 10)):
                self.exec_lief.add_import_function(added_libs[-1], generate_random_string())

        exe_build = lief.PE.Builder(self.exec_lief)
        exe_build.build_imports(True)
        exe_build.build()
        self.exec_lief=lief.PE.parse(list(bytearray(exe_build.get_build())))
        self.write()
        return 1
        # Not sure
        #self.exec_lief.optional_header.sizeof_code
        #self.exec_lief.optional_header.sizeof_initialized_data
        #self.exec_lief.optional_header.baseof_code
        #self.exec_lief.optional_header.baseof_data

        # Probably not
        #self.exec_lief.optional_header.win32_version_value

        #self.exec_lief.authentihash_md5()


output_folder="./Datasets/Binaries/test_final"
input_folder="./Datasets/Binaries/test/virut"

def main():
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    for root, _, files in os.walk(input_folder):
        family_folder = output_folder+"/"+root.split('/')[-1]
        if not os.path.exists(family_folder):
            os.makedirs(family_folder)
        for file_name in files:
            print("Working on "+file_name)
            input_file = os.path.join(root, file_name)
            output_file = os.path.join(family_folder, file_name)
            #if os.path.exists(output_file):
            #    continue
            shutil.copyfile(input_file, output_file)
            pe_binary = Obfuscator(output_file)
            works = pe_binary.metadata()
            if works == 0:
                continue
            pe_binary.addition(0.5)
            pe_binary.clone()
            pe_binary.injection(0.9)

        try:
            # Iterate through all files in the folder
            for filename in os.listdir(family_folder):
                file_path = os.path.join(family_folder, filename)

                # Check if it's a file (not a folder) and does not end with '_final'
                if os.path.isfile(file_path) and not filename.endswith('_final'):
                    print(f"Removing file: {file_path}")  # Optional: log the removed file
                    os.remove(file_path)

            print("Cleanup complete.")
        except Exception as e:
            print(f"An error occurred: {e}")



if __name__ == "__main__":
    main()

'''
TODO:
    - saving the file at each step
    - command line args
    - complete header attack, "fix" checksums
'''