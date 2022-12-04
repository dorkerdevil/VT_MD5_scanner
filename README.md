# vhash scanner
virustotal hash scanner - Public 

## About -
This Script is created to scan system and extracts md5 hash and match using virustotal api to identify weather the file is malicious or not.

## Requirements 
```bash
pip3 install hashlib
```
## Usage  
```bash
python3 vhash_scanner.py -f MD5HASH  (This tells if the given md5 is malicious or not) 
python3 vhash_scanner.py /path/to/directory (This will scan dir and subdir and extract their MD5 hash values)
# By Default it will save final result in Found.html else you can use > to save into the html file that you like
python3 vhash_scanner.py /path/to/directory > something.hml
```

## Credits
• [D0rkerDevil](https://twitter.com/D0rkerDevil)
