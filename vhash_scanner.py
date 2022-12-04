import hashlib
import os
import requests
from json.decoder import JSONDecodeError
#C0ded By D0rkerDevil 
# Replace these with your own VirusTotal API key and URL
API_KEY = "YOUR VIRUSTOTAL API KEY HERE"
VT_URL = "https://www.virustotal.com/vtapi/v2/file/report"

def is_malware(file_md5: str) -> bool:
    # Check if the file's MD5 hash matches any known malware hashes using VirusTotal's API
    params = {"apikey": API_KEY, "resource": file_md5}
    response = requests.get(VT_URL, params=params)
    
    try:
        # If the "positives" key is not present in the response, assume that the file is not malware
        if "positives" not in response.json():
            return False
        
        # If the "positives" key is present, return whether its value is greater than 0
        return response.json()["positives"] > 0
    except JSONDecodeError:
        # If an error occurred while parsing the JSON response, print an error message and return False
        print(f"Error: No Match Found for {file_md5}")
        return False


def scan_file(file_md5: str) -> str:
    if is_malware(file_md5):
        return f"{file_md5} is malware"
    else:
        return f"{file_md5} is not malware"


def update_html(filenames: list[str], md5_hashes: list[str]) -> str:
    # Create an empty list to store the updated HTML code
    updated_html = []
    
    # Open the HTML template file and read the lines
    with open("template.html", "r") as html_file:
        lines = html_file.readlines()
    
    # Loop through the lines in the HTML file
    for line in lines:
        # Check if the line contains the placeholder for the file name
        if "{file_name}" in line:
            # Loop through the file names and their corresponding MD5 hashes
            for (filename, md5_hash) in zip(filenames, md5_hashes):
                # Create a new line with the updated file name and MD5 hash
                updated_line = line.replace("{file_name}", filename).replace("{md5_hash}", md5_hash)
                # Add the updated line to the list
                updated_html.append(updated_line)
        else:
            # If the line does not contain the placeholder, add it to the list as-is
            updated_html.append(line)
    
    # Return the updated HTML code as a string
    return "".join(updated_html)


def scan_directory(dir_path: str) -> str:
    # Create an HTML document to store the results
    html_output = "<html><body><ul>"
    
    # Scan all files in the directory and its subdirectories
    for dir_name, subdir_list, file_list in os.walk(dir_path):
        for file_name in file_list:
            file_path = os.path.join(dir_name, file_name)
            
            # Calculate the MD5 hash of the file
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            file_md5 = hash_md5.hexdigest()
            
            if is_malware(file_md5):
                # If the file is malware, add it to the HTML document
                html_output += f"<li>{file_path} is malware</li>"
    
    # Finish the HTML document and return it
    html_output += "</ul></body></html>"
    return html_output

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        # If a single argument is provided, assume it is a directory path and scan the directory
        dir_path = sys.argv[1]
        print(scan_directory(dir_path))
    elif len(sys.argv) == 3:
        # If two arguments are provided, assume the first is the "-f" flag and the second is a file MD5 hash
        if sys.argv[1] == "-f":
            file_md5 = sys.argv[2]
            print(scan_file(file_md5))
    else:
        print("Usage: python scan_directory.py [-f] [directory or file MD5 hash]")

