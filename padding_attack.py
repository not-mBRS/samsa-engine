import os
import pefile
import csv
import random

# List of NOP equivalents
NOP_EQUIVALENTS = [
    b'\x83\xC0\x00',  # ADD EAX, 0
    b'\x83\xE8\x00',  # SUB EAX, 0
    b'\x6B\xC0\x01',  # IMUL EAX, EAX, 1
    b'\x8D\x40\x00',  # LEA EAX, [EAX + 0]
    b'\x0B\xC0',      # OR EAX, EAX
    b'\x23\xC0',      # AND EAX, EAX
    b'\xD9\xD0',      # FNOP
    b'\x89\xC0',      # MOV EAX EAX
    b'\x87\xC0'       # XCHG EAX EAX
]

def inject_random_nop_padding(file_path, nop_percentage=0.05, nop_code=None):
    file_size = os.path.getsize(file_path)

    with open(file_path, 'rb') as f:
        original_data = f.read()

    padding_size = 0x1000  # Define padding size (4 KB)

    if len(original_data) % padding_size != 0:
        raise ValueError("File size is not a multiple of padding size")

    start_padding_offset = len(original_data) - padding_size

    if nop_code is None:
        nop_code = random.choice(NOP_EQUIVALENTS)
    nop_code_size = len(nop_code)

    injection_size = int(padding_size * nop_percentage)
    if injection_size == 0:
        raise ValueError(f"Injection size is zero for {nop_percentage*100}% of padding space")

    if injection_size < nop_code_size:
        raise ValueError(f"Not enough padding space to inject {nop_code_size} byte NOP code")

    padding_data = bytearray(original_data[start_padding_offset:])
    padding_data[:injection_size] = nop_code * (injection_size // nop_code_size)
    modified_data = original_data[:start_padding_offset] + padding_data

    return modified_data, nop_code.hex()

def process_executables(input_folder, output_folder_base, csv_path, max_size_mb=5, nop_percentage=0.05):
    if not os.path.exists(output_folder_base):
        os.makedirs(output_folder_base)
        for root, _, files in os.walk(input_folder):
            for file_name in files:
                if file_name.endswith(".exe"):
                    file_path = os.path.join(root, file_name)
                    try:
                        # Determine if file size is smaller than max_size_mb
                        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                        if file_size_mb >= max_size_mb:
                            continue
                        # Perform NOP injection
                        modified_data, nop_code_hex = inject_random_nop_padding(file_path, nop_percentage)

                        output_file_path = os.path.join(output_folder_base, f"modified_{file_name}")
                        
                        # Write modified data to new file
                        with open(output_file_path, 'wb') as f:
                            f.write(modified_data)

                        print(f"Modified {file_name} with {nop_percentage*100}% NOP code at padding saved as {output_file_path}")

                    except Exception as e:
                        print(f"Error processing {file_name}: {e}")

input_folder = "/media/doonu/H/Problem_Space/Dummy/"
output_folder_base = "/media/doonu/H/Problem_Space/Manipulated_Executable_Padding/"
csv_path = "/media/doonu/H/Problem_Space/Modified_sections_log_padding.csv"
process_executables(input_folder, output_folder_base, csv_path)
