import requests as rq
import hashlib as hl


def compute_file_hash(filename):
        with open(filename,'rb') as f:
                file_bytes = f.read()
                file_hash = hl.sha256(file_bytes).hexdigest()
        return file_hash

def cheack_if_safe(file_hash):
    API_key = "ReplaceMe" # Replace the value with your API key
    url = ("https://www.virustotal.com/vtapi/v2/file/report?apikey=" + API_key)
    url += ("&resource=" + file_hash)
    response = rq.get(url)
    result = response.json()
    positves = result["positives"]
    total = result["total"]
    print(f"{positves} of {total} security vendors flagged this file as malicious")
    return 0


filename = input("Enter the filename you want to scan : ")
file_hash = compute_file_hash(filename)
result = cheack_if_safe(file_hash)
