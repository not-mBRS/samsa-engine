import shutil
import keystone as ks #    assembler
import capstone as cs # disassembler
import r2pipe

mutables = ['nop', 'mov', 'or', 'xor', 'sub', 'add', 'cmp', 'test', 'shl', 'lea', 'not']

class CloneEngine():
    def __init__(self) -> None:
        self.ks = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
        self.cs = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.cs.detail = True

def find_mut(meta, ins_analyzed):
    opcodes=[]
    mnemonics=[]
    new_inst=None
    breakpoint()
    for i in meta.cs.disasm(bytes.fromhex(ins_analyzed['bytes']), 0x0):
        mnemonics+=i.mnemonic
        opcodes+=i.op_str.split(',')
    if ins_analyzed['type'] == 'mov':
        if opcodes[0][-1]=='x' and opcodes[1] == ' 0':
            new_inst = 'xor {}, {};'.format(opcodes[0], opcodes[0]).encode()
        # mov reg, 0 -> xor reg, reg / xor reg, 0 / and reg, 0
        elif opcodes[0] != opcodes [1]:
            new_inst = 'push {}; pop {}; nop;'.format(opcodes[1].strip(), opcodes[0]).encode()
        # mov reg, reg2 -> push reg; pop reg2
        elif opcodes[0] == opcodes [1]:
            new_inst = 'nop;'.encode()
        # mov reg, reg -> nop
    #elif ins_analyzed['type'] == 'nop':
        # nop -> nop
    elif ins_analyzed['type'] == 'or':
        if opcodes[1] == ' 0':
        # or mem/reg, 0 -> nop
            new_inst = 'nop;'.encode()
        elif opcodes[0] == opcodes[1]:
            new_inst = 'test {}, {};'.format(opcodes[0], opcodes[0]).encode()
        # or reg, reg -> test reg, reg
    elif ins_analyzed['type'] == 'xor':
        if opcodes[1] == ' -1':
            new_inst = 'not {};'.format(opcodes[0]).encode()
        # xor reg/mem, -1 -> not reg/mem
        elif opcodes[1] == ' 0':
            new_inst = 'xor {}, {};'.format(opcodes[0], opcodes[0]).encode()
        # xor reg, 0 -> xor reg, reg 
        elif opcodes[1] == opcodes[0]:
            new_inst = 'sub {}, {};'.format(opcodes[0], opcodes[0]).encode()
        # xor reg, reg -> sub reg, reg
    elif ins_analyzed['type'] == 'sub':
        if opcodes[0] == opcodes[1]:
            new_inst = 'xor {}, {};'.format(opcodes[0], opcodes[0]).encode()
        # sub reg, reg -> xor reg, reg
        else:
            new_inst = 'add {}, {};'.format(opcodes[0], "-"+opcodes[0].strip()).encode()
        # sub reg/mem, imm -> add reg/mem, -imm
    elif ins_analyzed['type'] == 'add':
        if opcodes[0] != opcodes[1]:
            new_inst = 'sub {}, {};'.format(opcodes[0], "-"+opcodes[0].strip()).encode()
        # add reg, imm -> sub reg, -imm
        elif opcodes[0] == opcodes[1]:
            new_inst = 'shl {}, 1;'.format(opcodes[0]).encode()
        # add reg, reg -> shl reg, 1
    elif ins_analyzed['type'] == 'cmp':
        if opcodes[1] == ' 0':
            new_inst = 'test {}, {};'.format(opcodes[0], opcodes[0]).encode()
        # cmp reg, 0 -> test reg reg / and reg, reg / or reg, reg
    elif ins_analyzed['type'] == 'test':
        if opcodes[0] == opcodes[1]:
            new_inst = 'or {}, {};'.format(opcodes[0], opcodes[0]).encode()
        # test reg, reg -> or reg, reg
    elif ins_analyzed['type'] == 'shl':
        if opcodes[1] == ' 1':
            new_inst = 'add {}, {};'.format(opcodes[0], opcodes[0]).encode()
        # shl reg, 1 -> add reg, reg
    #elif ins_analyzed['type'] == 'lea':
        # lea reg, [imm] -> add mov, imm
        # lea reg, [reg+imm] -> add reg, imm (fino a 127)
        # lea reg, [reg2] -> add reg, reg2
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
                asm, _ = meta.ks.asm(mut)
                bytesArr = ''.join(['{:02x}'.format(ins) for ins in asm])
                list_mutations.append(
                    {'offset': ins_analyzed['offset'],
                     'bytes': bytesArr})
        counter+=1
        
    return list_mutations

def patch_executable(r2, mutations):
    for idx, mutation in enumerate(mutations):
        r2.cmd(f"wx {mutation['bytes']} @{mutation['offset']}")

input="./calc_try.exe"
output="./calc_try_mod.exe"

if __name__ == '__main__':
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
            patch_executable(r2, meta, mutations)

        r2.quit()

