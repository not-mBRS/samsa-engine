import os
import pefile
import csv
import random

NOP_EQUIVALENTS = [
    b'\x83\xC0\x00',  # ADD EAX, 0
    b'\x83\xE8\x00',  # SUB EAX, 0
    b'\x6B\xC0\x01',  # IMUL EAX, EAX, 1
    b'\x8D\x40\x00',  # LEA EAX, [EAX + 0]
    b'\x0B\xC0',      # OR EAX, EAX
    b'\x23\xC0',      # AND EAX, EAX
    b'\xD9\xD0',      # FNOP
    b'\x89\xC0',      # MOV EAX, EAX
    b'\x87\xC0',      # XCHG EAX, EAX
]

def find_text_section(pe):
    for section in pe.sections:
        if section.Name.decode(errors='ignore').startswith('.text'):
            return section
    raise ValueError("No .text section found for modification")

def get_slack_space(section_data):
    zero_count = 0
    for byte in reversed(section_data):
        if byte == 0x00:
            zero_count += 1
        else:
            break
    return zero_count

def inject_nop_in_text_section(file_path, nop_percentage=0.05, nop_code=None):
    pe = pefile.PE(file_path)
    text_section = find_text_section(pe)
    
    section_data = text_section.get_data()
    zero_count = get_slack_space(section_data)

    if zero_count == 0:
        raise ValueError(f"No contiguous zero bytes found in section .text")

    injection_size = int(zero_count * nop_percentage)
    if injection_size == 0:
        raise ValueError(f"Injection size is zero for {nop_percentage*100}% of slack space")

    if nop_code is None:
        nop_code = random.choice(NOP_EQUIVALENTS)

    nop_code_size = len(nop_code)
    if injection_size < nop_code_size:
        raise ValueError(f"Not enough slack space in .text section to inject {nop_code_size} byte NOP code")

    last_free_space_offset = len(section_data) - zero_count
    file_offset = text_section.PointerToRawData + last_free_space_offset

    # Modify the file by injecting NOP equivalent code
    with open(file_path, 'rb') as f:
        original_data = f.read()

    modified_data = (
        original_data[:file_offset] +
        nop_code +
        original_data[file_offset + nop_code_size:])

    return modified_data, '.text', nop_code.hex()

def process_executables(input_folder, output_folder_base, csv_path):
    if not os.path.exists(output_folder_base):
        os.makedirs(output_folder_base)

    # Read existing CSV entries
    processed_files = {}
    if os.path.exists(csv_path):
        with open(csv_path, mode='r') as csv_file:
            csv_reader = csv.reader(csv_file)
            next(csv_reader) 
            for row in csv_reader:
                key = (row[0], row[1], row[2])
                processed_files[key] = (row[3], row[4])

    with open(csv_path, mode='a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["File Name", "Modified Section", "NOP Code Inserted", "Status", "Error Message"])

        for root, _, files in os.walk(input_folder):
            for file_name in files:
                if file_name.endswith(".exe"):
                    file_path = os.path.join(root, file_name)
                    family_name = os.path.basename(root)
                    
                    for i in range(5, 101, 10):
                        nop_percentage = i / 100.0
                        output_folder = os.path.join(output_folder_base, str(i))
                        output_subfolder = os.path.join(output_folder, family_name)
                        os.makedirs(output_subfolder, exist_ok=True)

                        try:
                            key = (file_name, ".text")
                            if key not in processed_files:
                                # Inject NOP into .text section
                                modified_data, section_name, nop_code_hex = inject_nop_in_text_section(file_path, 1.0)
                                processed_files[key] = (section_name, nop_code_hex)
                            else:
                                section_name, nop_code_hex = processed_files[key]

                            output_file_path = os.path.join(output_subfolder, f"modified_{i}_{file_name}")
                            modified_data, _, _ = inject_nop_in_text_section(file_path, nop_percentage, bytes.fromhex(nop_code_hex))

                            if (file_name, section_name, nop_code_hex) not in processed_files:
                                csv_writer.writerow([file_name, section_name, nop_code_hex, "Success", "None"])
                                processed_files[(file_name, section_name, nop_code_hex)] = ("Success", "None")

                            with open(output_file_path, 'wb') as f:
                                f.write(modified_data)

                            print(f"Modified {file_name} with {nop_percentage*100}% NOP code in {section_name} saved as {output_file_path}")

                        except Exception as e:
                            print(f"Error processing {file_name}: {e}")
                            csv_writer.writerow([file_name, "N/A", "N/A", "Failed", str(e)])


input_folder = "/media/doonu/H/Problem_Space/Dummy_2/"
output_folder_base = "/media/doonu/H/Problem_Space/Dummy_Manipulated_Executable_NOP/"
csv_path = "/media/doonu/H/Problem_Space/Modified_sections_log.csv"


process_executables(input_folder, output_folder_base, csv_path)
