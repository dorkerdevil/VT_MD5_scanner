import hashlib
import os
import requests
from json.decoder import JSONDecodeError
#C0ded By D0rkerDevil 

API_KEY = "YOUR VIRUSTOTAL API KEY HERE"
VT_URL = "https://www.virustotal.com/vtapi/v2/file/report"

def is_malware(file_md5: str) -> bool:
    
    params = {"apikey": API_KEY, "resource": file_md5}
    response = requests.get(VT_URL, params=params)
    
    try:
        
        if "positives" not in response.json():
            return False
        
        
        return response.json()["positives"] > 0
    except JSONDecodeError:
        
        print(f"Error: No Match Found for {file_md5}")
        return False


def scan_file(file_md5: str) -> str:
    if is_malware(file_md5):
        return f"{file_md5} is malware"
    else:
        return f"{file_md5} is not malware"


def update_html(filenames: list[str], md5_hashes: list[str]) -> str:
    
    updated_html = []
    
    
    with open("Found.html", "r") as html_file:
        lines = html_file.readlines()
    
   
    for line in lines:
        
        if "{file_name}" in line:
            
            for (filename, md5_hash) in zip(filenames, md5_hashes):
                
                updated_line = line.replace("{file_name}", filename).replace("{md5_hash}", md5_hash)
                
                updated_html.append(updated_line)
        else:
            
            updated_html.append(line)
    
    
    return "".join(updated_html)


def scan_directory(dir_path: str) -> str:
    
    html_output = "<html><body><ul>"
    
    
    for dir_name, subdir_list, file_list in os.walk(dir_path):
        for file_name in file_list:
            file_path = os.path.join(dir_name, file_name)
            
            
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            file_md5 = hash_md5.hexdigest()
            
            if is_malware(file_md5):
                
                html_output += f"<li>{file_path} is malware</li>"
    
    
    html_output += "</ul></body></html>"
    return html_output

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        
        dir_path = sys.argv[1]
        print(scan_directory(dir_path))
    elif len(sys.argv) == 3:
        
        if sys.argv[1] == "-f":
            file_md5 = sys.argv[2]
            print(scan_file(file_md5))
    else:
        print("Usage: python scan_directory.py [-f] [directory or file MD5 hash]")

