import os
import json
import hashlib
import requests
import csv
import time


API_KEY = 'your_api_key_here'
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

def upload_file(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        response = requests.post(url, headers=HEADERS, files=files)
    
    if response.status_code == 200:
        response_json = response.json()
        analysis_id = response_json['data']['id']
        print(f"Uploaded {file_path}, analysis ID: {analysis_id}")
        return analysis_id
    else:
        print(f"Failed to upload {file_path}: {response.status_code} - {response.text}")
        return None

def get_report(analysis_id, retries=5, wait_time=10):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'    
    for _ in range(retries):
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            report_json = response.json()
            if report_json['data']['attributes']['status'] == 'completed':
                print(f"Report is ready for analysis ID: {analysis_id}")
                return report_json
            else:
                print(f"Waiting for report (analysis ID: {analysis_id})...")
                time.sleep(wait_time)
        else:
            print(f"Error fetching report for {analysis_id}: {response.status_code}")
            time.sleep(wait_time)
    
    print(f"Report not ready after {retries} retries.")
    return None

def extract_community_score(report_json):
    if not report_json or "data" not in report_json:
        print("Invalid report JSON format")
        return 0    
    results = report_json.get("data", {}).get("attributes", {}).get("results", {})
    malicious_count = sum(1 for engine in results.values() if engine.get('category') == 'malicious')
    
    return malicious_count

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

def process_executable(original_file_path, modified_folders, report_folder_base, csv_writer):
    original_name = os.path.basename(original_file_path)
    original_report_file = os.path.join(report_folder_base, "original", f"{original_name}.json")
    
    if not os.path.exists(original_report_file):
        print(f"Uploading {original_name} to VirusTotal...")
        analysis_id = upload_file(original_file_path)
        if analysis_id:
            original_report = get_report(analysis_id)
            if original_report:
                save_report(original_report, original_report_file)
                original_score = extract_community_score(original_report)
            else:
                original_score = 0
        else:
            original_score = 0
    else:
        original_report = read_json_file(original_report_file)
        original_score = extract_community_score(original_report) if original_report else 0
    
    modified_scores = []
    for subfolder, folder_path in modified_folders.items():
        modified_file_path = os.path.join(folder_path, f"modified_{original_name}")
        if os.path.exists(modified_file_path):
            modified_report_file = os.path.join(report_folder_base, subfolder, f"modified_{original_name}.json")
            if not os.path.exists(modified_report_file):
                print(f"Uploading modified {original_name} to VirusTotal")
                analysis_id = upload_file(modified_file_path)
                if analysis_id:
                    modified_report = get_report(analysis_id)
                    if modified_report:
                        save_report(modified_report, modified_report_file)
                        modified_score = extract_community_score(modified_report)
                    else:
                        modified_score = 0
                else:
                    modified_score = 0
            else:
                modified_report = read_json_file(modified_report_file)
                modified_score = extract_community_score(modified_report) if modified_report else 0
        else:
            print(f"Modified executable does not exist: {modified_file_path}")
            modified_score = 0
        
        modified_scores.append(modified_score)

    csv_writer.writerow([original_name, original_score] + modified_scores)
    print(f"Processed {original_name} with scores: Original - {original_score}, Modified - {modified_scores}")

def get_modified_folders(base_folder):
    modified_folders = {}
    for subfolder in sorted(os.listdir(base_folder)):
        subfolder_path = os.path.join(base_folder, subfolder)
        if os.path.isdir(subfolder_path):
            modified_folders[subfolder] = subfolder_path
    return modified_folders

def process_reports(original_base_folder, modified_base_folder, report_folder_base, csv_path):
    os.makedirs(os.path.join(report_folder_base, "original"), exist_ok=True)
    modified_folders = get_modified_folders(modified_base_folder)
    
    for subfolder in modified_folders.values():
        os.makedirs(os.path.join(report_folder_base, subfolder), exist_ok=True)

    with open(csv_path, mode='w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Original Executable", "Original Score"] + [f"{folder}%" for folder in sorted(modified_folders.keys())])
        
        for root, dirs, files in os.walk(original_base_folder):
            for file in files:
                if file.endswith(".exe"):
                    process_executable(os.path.join(root, file), modified_folders, report_folder_base, csv_writer)


original_base_folder = "/media/doonu/H/Problem_Space/Dummy"
modified_base_folder = "/media/doonu/H/Problem_Space/Manipulated Executable NOP"
report_folder_base = "/media/doonu/H/Problem_Space/Reports/"
csv_path = "/media/doonu/H/Problem_Space/Community_Score/dummy_community_scores.csv"

process_reports(original_base_folder, modified_base_folder, report_folder_base, csv_path)
