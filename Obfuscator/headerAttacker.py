import os
import shutil
import pefile
import r2pipe

'''
Things that can be modified without breaking everything:
- COFF Header timestamp
- PE CLR Runtime Size
- PE CLR Runtime Virtual Address
- Section names
- overlay
- Major Image Version
- Minor Image Version
- Major Linker Version
- Minor Linker Version
- Major OS Version
- Minor OS Version
- Major Subsystem Version
- Minor Subsystem Version
- Strings?
- some sizes


'''

def attack_header(pe_file_handler):
    pe_file_handler.DOS_HEADER
    pe_file_handler.NT_HEADERS
    pe_file_handler.FILE_HEADER
    pe_file_handler.OPTIONAL_HEADER




def process_executables(input_folder, outptut_folder, percentage=.5):
    for root, _, files in os.walk(input_folder):
        for file_name in files:
            input_file = os.path.join(root, file_name)
            family_folder = output_folder+"/"+str(int(percentage*100))+"/"+root.split('/')[-1]
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
                    pe = pefile.PE(output_file)
                    attack_header(pe)
                    pe.write(output_file)


input_folder = "./prova"     
output_folder = "./prova_2"    
def main():
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        process_executables(input_folder, output_folder)

if __name__ == "__main__":
    main()