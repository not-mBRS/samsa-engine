import csv

def extract_file_names(input_csv, output_txt):
    # List to store the file names that meet the constraint
    matching_files = []

    # Open the input CSV file
    with open(input_csv, mode='r', newline='') as csv_file:
        csv_reader = csv.reader(csv_file)
        
        # Iterate over each row in the CSV file
        for row in csv_reader:
            # Check if the row has at least three columns
            if len(row) >= 3:
                # Check if the second column is the same as the third
                if row[1] == row[2]:
                    # Append the file name from the first column to the list
                    matching_files.append(row[0])

    # Write the matching file names to the output text file
    with open(output_txt, mode='w') as output_file:
        for file_name in matching_files:
            output_file.write(file_name + '\n')

    print(f"Extracted {len(matching_files)} file names that meet the constraint to '{output_txt}'.")

# Example usage
input_csv = 'results100.csv'  # Replace with your input CSV file path
output_txt = 'results_imbroccate100.txt'  # Replace with desired output text file path
#extract_file_names(input_csv, output_txt)

lista_correct = []

with open(input_csv, mode='r', newline='') as csv_file:
    csv_reader = csv.reader(csv_file)

    for row in csv_reader:
        if row[1] == row[2]:
            lista_correct.append(row[0])

with open(output_txt, mode='w') as output_file:
    for file_name in lista_correct:
        output_file.write(file_name + '\n')