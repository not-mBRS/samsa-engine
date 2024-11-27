import requests as rq
from ratelimit import limits, sleep_and_retry
import json
import random
import sys

API_KEY_VS = "2wOAfRgt9mMFqrMnihtCAUD5nduzVBCD"
API_KEY_VT = "141c660fd9f84dbb651621a555bfd82f818a05d55d7ad3d5b595e3a0d431fb44"
API_KEY_MB = "c873c6eee2c73792f97a0c8a3cbb9892"

failed=[]

@sleep_and_retry
@limits(calls=3, period=60)
def call_vs_api(url):
    response = rq.get(url)
    print("Virus Share: ",response.status_code)
    if response.status_code==204:
        pass#quit()
    if response.status_code !=200:
        return str(response.status_code)
    return json.dumps(response.json())

@sleep_and_retry
@limits(calls=3, period=60)
def call_vt_api(url, headers):
    response = rq.get(url, headers=headers)
    print("Virus Total: ",response.status_code)
    if response.status_code==429:
        quit()
    if response.status_code !=200:
        return str(response.status_code)
    return json.dumps(response.json())

@sleep_and_retry
@limits(calls=3, period=60)
def call_mb_api(url, data):
    response = rq.post(url, data)
    print("Malware Bazaar: ",response.status_code)
    if response.status_code != 200:
        return str(response.status_code)
    return json.dumps(response.json())

@sleep_and_retry
@limits(calls=3, period=60)
def query_API(hashes_list, zip_num):
    headers = {"x-apikey": API_KEY_VT}
    url_mb = "https://mb-api.abuse.ch/api/v1/"
    _=0
    while True:
        _+=1
        print("iteration: "+str(_))
        url_vs = "https://virusshare.com/apiv2/file?apikey={api_key}&hash={hash_string}".format(api_key=API_KEY_VS, hash_string=hashes_list[_])
        output_vs_file = json.loads(call_vs_api(url_vs))
        try:
            if output_vs_file["exif"]["FileTypeExtension"] != "exe":
                print(output_vs_file["exif"]["FileTypeExtension"])
                print("not an exe")
                with open("Dataset/Hashes/Saved/VirusShare_{zip}_saved.md5".format(zip=zip_num), "a") as f:
                    f.write(hashes_list[_]+'\n')
                continue
        except:
            with open("Dataset/Hashes/Saved/VirusShare_{zip}_saved.md5".format(zip=zip_num), "a") as f:
                f.write(hashes_list[_]+'\n')
            continue
        url_vt = "https://www.virustotal.com/api/v3/files/{hash_string}".format(hash_string=hashes_list[_])
        output_vt_file = call_vt_api(url_vt,headers)
        # Query VirusTotal
        with open("Reports/VT/{zip}/VTReport_".format(zip=zip_num)+hashes_list[_]+".json", 'w') as f:
            f.write(output_vt_file)
        data={'query':'get_info', 'hash':'{hash_string}'.format(hash_string=hashes_list[_])}
        output_mb_file = call_mb_api(url_mb, data)
        # Query MalwareBazaar
        with open("Reports/MB/{zip}/MBReport_".format(zip=zip_num)+hashes_list[_]+".json", 'w') as f:
            f.write(output_mb_file)
        with open("Dataset/Hashes/Saved/VirusShare_{zip}_saved.md5".format(zip=zip_num), "a") as f:
            f.write(hashes_list[_]+'\n')
    print("Finish!")

def main():
    mal_hashes=[]
    if len(sys.argv) < 2: 
        print("usage: Fetch_Reports <VirusShare_hashes>")
        return
    else:
        zip_num = sys.argv[1]
    #with open("Dataset/Hashes/VirusShare_{zip}_filter.md5".format(zip=zip_num), "r") as f:
    with open("Dataset/Hashes/VirusShare_{zip}_filter.md5".format(zip=zip_num), "r") as f:
        mal_hashes = f.readlines()
    with open("Dataset/Hashes/Saved/VirusShare_{zip}_saved.md5".format(zip=zip_num), "r") as fs:
        mal_hashes_already_done=fs.readlines()
    final_hashes=[]
    for x in mal_hashes:
        if x not in mal_hashes_already_done:
            final_hashes.append(x)
    for i in range(len(final_hashes)):
        final_hashes[i] = final_hashes[i].strip('\n')
    shuf_hashes = random.sample(final_hashes, len(final_hashes))
    query_API(final_hashes, zip_num)


if __name__ == "__main__":
    main()