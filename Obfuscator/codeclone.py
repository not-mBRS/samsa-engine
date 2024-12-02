import shutil
import keystone as ks #    assembler
import capstone as cs # disassembler
import r2pipe

mutables = ['nop', 'mov', 'or', 'xor', 'sub', 'add']

class CloneEngine():
    def __init__(self) -> None:
        self.ks = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
        self.cs = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)

def find_mut(meta, ins_analyzed):
    
    breakpoint()
    opcodes=[]
    mnemonics=[]
    for i in meta.cs.disasm(bytes.fromhex(ins_analyzed['bytes']), 0x0):
        mnemonics+=[i.mnemonic]
        opcodes+=[i.op_str.split(',')]
    daje = 'push {}; pop {}; nop'.format(opcodes[0][1], opcodes[0][0])
    return daje


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

input="../tmp/calc.exe"
output="../tmp/calc_try.exe"

if __name__ == '__main__':
    breakpoint()
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

