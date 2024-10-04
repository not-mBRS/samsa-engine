import requests as rq
from ratelimit import limits, sleep_and_retry
import json
import os
import random
import sys
import time

API_KEY_VT = open("api.txt", "r").readline()
HEADERS = {
        "accept": "application/json",
        "x-apikey": API_KEY_VT
        }
#@sleep_and_retry
#@limits(calls=3, period=60)
def call_vt_api(url, headers, filez):
    response = rq.request('POST', url, headers=headers, files=filez)
    print("Virus Total: ",response.status_code)

    if response.status_code==429:
        time.sleep(100)
    if response.status_code !=200:
        print("Error in request")
        return 0
    if response:
        return response.json()['data']['id']

# copied functions
def api_request(url, method='GET', files=None):
    retries = 10
    wait_time = 10
    for _ in range(retries):
        response = rq.request(method, url, headers=HEADERS, files=files)
        if response.status_code == 200:
            return response.json()
        print(f"Error {method} {url}: {response.status_code}")
        time.sleep(wait_time)
    return None
def get_report(analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    report_json = api_request(url)
    if report_json:
        count=0
        while report_json['data']['attributes']['status'] != 'completed':
            print("waiting for analysis completion...")
            report_json = api_request(url)
            time.sleep(10)
            count+=1
            if count==100:
                exit()
        return report_json
    return {}
def save_report(report_json, report_path):
    with open(report_path, 'w') as json_file:
        json.dump(report_json, json_file, indent=4)
    print(f"Saved report to {report_path}")
    
def query_API(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    response = call_vt_api(url, headers=HEADERS, filez=files)
    if response:
        original_report = get_report(response)
        if original_report:
            save_report(original_report, "./Reports2/"+file_path.split("/")[-3]+"/VTReport_"+file_path.split("/")[-1]+".json")


def main():
    file_paths = []
    # Walk through the directory
    for dirpath, _, filenames in os.walk("./dataset/mutations"):
        for filename in filenames:
            file_paths.append(os.path.join(dirpath, filename))
    for f in file_paths:
        if os.path.exists("./Reports2/"+f.split("/")[-3]+"/VTReport_"+f.split("/")[-1]+".json"):
            print("Skipped")
            continue
        else:
            query_API(f)


if __name__ == "__main__":
    main()
