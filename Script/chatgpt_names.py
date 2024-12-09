
# Define the file paths
file1_path = '../Results/names_correct_add.txt'  # Replace with your first file path
file2_path = '../Results/names_correct_add_xor.txt'  # Replace with your second file path
output_path = '../Results/corruptedC.txt'  # Output file for names only in file1

# Read names from the first file
with open(file1_path, 'r') as file1:
    names_file1 = set(name.strip() for name in file1)

# Read names from the second file
with open(file2_path, 'r') as file2:
    names_file2 = set(name.strip() for name in file2)

# Find names that are in the first file but not in the second
unique_names = sorted(names_file1 - names_file2)  # Sort the unique names
# Write the result to the output file
with open(output_path, 'w') as output_file:
    for name in unique_names:
        output_file.write(name + '\n')

print(f"Names unique to {file1_path} have been saved in {output_path}")
