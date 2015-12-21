VirusTotal
==========
Python scripts to interact with the virustotal.com [Public API](https://www.virustotal.com/en/documentation/public-api/)

## Dependencies
python requests module (pip install requests) - this is essential only when uploading files for scan

## How to use
### Get api key
Register to get your api key from [virustotal](https://www.virustotal.com)
### update key in file
Take your key from [here](https://www.virustotal.com/en/user/appsec/apikey/) and add it to virustotal.py
```
self.api_key = '<-- YOUR API KEY HERE -->'
```
Alternatively, use (see usage): 
```
vt.setkey('___KEY___')
```

### Import 
``` 
from virustotal import vt
vt = vt()
```

### update api key
```
vt.setkey('___KEY___')
```

### API calls
* Retrieving file scan reports (file/hash)
```
vt.getfile('path/to/filename.ext')
vt.getfile('ee0fc30726c6dc1ef9ed15809c58d2bb438456ab')
```

* Retrieving URL/IP/Domain scan reports
```
vt.geturl('https://github.com/nu11p0inter/')
vt.getip('98.76.54.32')
vt.getdoamin('github.com')
```

* Sending and scanning files
```
vt.scanfile('path/to/file.ext')
```

* Sending and scanning URLs
```
vt.scanurl('http://github.com/nu11p0inter.com')
```

* Rescanning already submitted files (file/hash)
```
vt.rescan('file.ext')
vt.rescan('ee0fc30726c6dc1ef9ed15809c58d2bb438456ab')
```

* Comment on existing report
```
hash = open(file, 'rb').read()
msg = "#Malware @https://github.com/nu11p0inter/virustotal/"
vt.comment(hash, msg)
```


## Authors
Tal Melamed <github@appsec.it>
https://github.com/nu11p0inter/
