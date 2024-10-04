import os
import numpy as np
import tensorflow as tf
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score

# Load the trained model
model_path = 'dmalconv.h5'

# Constants
input_dim = 257  # Byte values + padding character
maxlen = (2**21)  # 2MB
padding_char = 256  # Padding byte

# Function to convert file content to numpy array
def bytez_to_numpy(bytez, maxlen=maxlen):
    b = np.ones((maxlen,), dtype=np.uint16) * padding_char
    bytez_content = bytez.read()
    bytez = np.frombuffer(bytez_content[:maxlen], dtype=np.uint8)
    b[:len(bytez)] = bytez
    return b

# Function to process executable file or directory and make predictions
def process_file_or_directory(model, path):
    # If it's a single file, just process that file
    if os.path.isfile(path):
        file_paths = [path]
    elif os.path.isdir(path):  # If it's a directory, process all files in it
        file_paths = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    else:
        print(f"Error: Path {path} is neither a file nor a directory.")
        return [], []

    predictions = []
    true_labels = []

    for file_path in file_paths:
        print(f"Processing file: {file_path}")
        with open(file_path, 'rb') as f:
            bytez = bytez_to_numpy(f)
            print(f"Byte data shape: {bytez.shape}")
            bytez = np.expand_dims(bytez, axis=0)
            print(f"Expanded byte data shape: {bytez.shape}")
            pred = model.predict(bytez)
            print(f"Raw prediction: {pred}")
            pred_class = 1 if pred[0][0] > 0.5 else 0 
            print(f"Predicted class: {pred_class}")
            predictions.append(pred_class)

        # Determine true label based on filename
        if "benign" in file_path.lower():
            true_labels.append(0)
        elif "malware" in file_path.lower():
            true_labels.append(1)
        else:
            print(f"Warning: Could not determine true label for {file_path}")
            true_labels.append(1)  # Default to malware if unclear
        
        print(f"True label: {true_labels[-1]}, Predicted: {predictions[-1]}")
    
    print("All true labels:", true_labels)
    print("All predictions:", predictions)
    return true_labels, predictions

# Function to calculate metrics
def calculate_metrics(true_labels, predictions):
    accuracy = accuracy_score(true_labels, predictions
    print(f"True Labels: {true_labels}")
    print(f"Predictions: {predictions}")
    print(f"Accuracy: {accuracy:.4f}")
    

# Custom prediction function
def custom_predict(model, bytez):
    pred = model.predict(bytez)
    if pred.shape == (1, 2):
        return 1 if pred[0][0] > pred[0][1] else 0
    else:
        return np.argmax(pred)

# Main function to load model and test on executables
def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 test.py /path/to/executable_or_directory")
        sys.exit(1)

    test_path = sys.argv[1]
    
    # Load pre-trained model
    model = tf.keras.models.load_model(model_path)
    
    # Debug: Print model summary
    model.summary()

    # Process the test file(s)
    true_labels, predictions = process_file_or_directory(model, test_path)
    
    # Check if we got any valid results
    if true_labels and predictions:
        calculate_metrics(true_labels, predictions)
    else:
        print("No valid files processed. Please check your input path and file labels.")

if __name__ == '__main__':
    main()
