import os
import json
import hashlib
import requests
import csv
import time

API_KEY = '75646191efded01c9985d7433971552a5032a8421d3e026ebbb6e0832b0729ba'
HEADERS = {
    'accept': 'application/json',
    'x-apikey': API_KEY
}

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def api_request(url, method='GET', files=None):
    retries = 10
    wait_time = 10
    for _ in range(retries):
        response = requests.request(method, url, headers=HEADERS, files=files)
        if response.status_code == 200:
            return response.json()
        print(f"Error {method} {url}: {response.status_code}")
        time.sleep(wait_time)
    return None

def upload_file(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    response_json = api_request(url, method='POST', files=files)
    if response_json:
        analysis_id = response_json['data']['id']
        return analysis_id
    return None

def get_report(analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    
    retries = 10  # Number of retries
    wait_time = 30  # Time to wait between retries (in seconds)
    
    for attempt in range(retries):
        report_json = api_request(url)
        if report_json:
            status = report_json['data']['attributes']['status']
            if status == 'completed':
                return report_json
            else:
                print(f"Report not ready (status: {status}). Retry {attempt + 1}/{retries}. Waiting {wait_time} seconds...")
        time.sleep(wait_time)
    
    print(f"Failed to get report for analysis ID {analysis_id} after {retries} retries.")
    return None

def extract_community_score(report_json):
    results = report_json.get("data", {}).get("attributes", {}).get("results", {})
    return sum(1 for engine in results.values() if engine.get('category') == 'malicious')

def save_report(report_json, report_path):
    with open(report_path, 'w') as json_file:
        json.dump(report_json, json_file, indent=4)
    print(f"Saved report to {report_path}")

def read_json_file(file_path):
    try:
        with open(file_path, 'r') as json_file:
            return json.load(json_file)
    except Exception as e:
        print(f"Error reading JSON file {file_path}: {e}")
        return None

def get_modified_folders(base_folder):
    modified_folders = {}
    for subfolder in sorted(os.listdir(base_folder)):
        subfolder_path = os.path.join(base_folder, subfolder)
        if os.path.isdir(subfolder_path):
            for root, _, files in os.walk(subfolder_path):
                for file in files:
                    if file.startswith("modified_") and file.endswith(".exe"):
                        modified_folders.setdefault(subfolder, []).append(os.path.join(root, file))
    return modified_folders

def process_executable(original_file_path, modified_folders, report_folder_base, csv_writer):
    original_name = os.path.basename(original_file_path)
    original_report_file = os.path.join(report_folder_base, "original", f"{original_name}.json")
    
    # Check if the report already exists for the original file
    if os.path.exists(original_report_file):
        print(f"Report for {original_name} already exists. Skipping.")
    else:
        # Upload original file and get report if it doesn't already exist
        analysis_id = upload_file(original_file_path)
        if analysis_id:
            original_report = get_report(analysis_id)
            if original_report:
                save_report(original_report, original_report_file)
            else:
                print(f"Failed to get report for {original_name}")
        else:
            print(f"Failed to upload {original_name}")
    
    original_score = extract_community_score(read_json_file(original_report_file)) if os.path.exists(original_report_file) else 0
    
    modified_scores = []
    for subfolder, files in sorted(modified_folders.items()):
        matching_file = next((file for file in files if original_name in file), None)
        if matching_file:
            modified_report_file = os.path.join(report_folder_base, subfolder, f"modified_{original_name}.json")
            
            # Check if the report already exists for the modified file
            if os.path.exists(modified_report_file):
                print(f"Report for modified {original_name} in {subfolder} already exists. Skipping.")
            else:
                # Upload modified file and get report if it doesn't already exist
                analysis_id = upload_file(matching_file)
                if analysis_id:
                    modified_report = get_report(analysis_id)
                    if modified_report:
                        save_report(modified_report, modified_report_file)
                    else:
                        print(f"Failed to get report for modified {original_name}")
                else:
                    print(f"Failed to upload modified {original_name}")
                    
            modified_score = extract_community_score(read_json_file(modified_report_file)) if os.path.exists(modified_report_file) else 0
        else:
            print(f"Modified executable does not exist in subfolders for: {original_name}")
            modified_score = 0
        
        modified_scores.append(modified_score)

    csv_writer.writerow([original_name, original_score] + modified_scores)
    print(f"Processed {original_name} with scores: Original - {original_score}, Modified - {modified_scores}")

def process_reports(original_folder, modified_base_folder, report_folder_base, csv_path):
    os.makedirs(os.path.join(report_folder_base, "original"), exist_ok=True)
    
    modified_folders = get_modified_folders(modified_base_folder)
    
    for subfolder in sorted(modified_folders.keys()):
        os.makedirs(os.path.join(report_folder_base, subfolder), exist_ok=True)

    header_columns = ["Original Executable", "Original Score"] + sorted(modified_folders.keys(), key=lambda x: int(x))
    
    with open(csv_path, mode='w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(header_columns)
        
        for root, _, files in os.walk(original_folder):
            for file in files:
                if file.endswith(".exe"):
                    process_executable(os.path.join(root, file), modified_folders, report_folder_base, csv_writer)

# Define paths
original_folder = "/media/doonu/H/Malware/"
modified_base_folder = "/media/doonu/H/Problem_Space/Padded_Manipulated Executable/"
report_folder_base = "/media/doonu/H/Problem_Space/Reports_Padded/"
csv_path = "/media/doonu/H/Problem_Space/Community_Score/padded_community_scores.csv"

process_reports(original_folder, modified_base_folder, report_folder_base, csv_path)
