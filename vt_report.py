import requests as rq
from ratelimit import limits, sleep_and_retry
import json
import random
import sys

API_KEY_VT = open("api.txt", "r").readline()

#@sleep_and_retry
#@limits(calls=3, period=60)
def call_vt_api(url, headers):
    response = rq.get(url, headers=headers)
    print("Virus Total: ",response.status_code)
    if response.status_code==429:
        quit()
    if response.status_code !=200:
        return str(response.status_code)
    return json.dumps(response.json())

#@sleep_and_retry
#@limits(calls=3, period=60)
def query_API(hashes_list):
    headers = {'accept': 'application/json',
               "x-apikey": API_KEY_VT
               }
    _=0
    for hash in hashes_list:
        _+=1
        print("iteration: "+str(_))
        url_vt = "https://www.virustotal.com/api/v3/files/{hash_string}".format(hash_string=hash)
        output_vt_file = call_vt_api(url_vt,headers)
        with open("./Reports/VTReport_"+hash+".json", 'w') as f:
            f.write(output_vt_file)
    print("Finish!")


def main():
    mal_hashes=[]
    if len(sys.argv) < 2: 
        print("usage: vt_report.py <hashes>")
        return
    with open(sys.argv[1], "r") as f:
        mal_hashes = f.readlines()
    for i in range(len(mal_hashes)):
        mal_hashes[i] = mal_hashes[i].strip('\n').split(" ")[1]
    query_API(mal_hashes)


if __name__ == "__main__":
    main()
