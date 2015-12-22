![virustotal Logo](https://virustotalcloud.appspot.com/static/img/logo-small.png)
VirusTotal Public API
==========
Python scripts to interact with the virustotal.com [Public API](https://www.virustotal.com/en/documentation/public-api/)

## Dependencies
python requests module (pip install requests) - essential only when uploading files for scan

## How to use
### Get api key
Register to get your api key from [virustotal](https://www.virustotal.com)
### Update key in file
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

### Update api key
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
vt.getdomain('github.com')
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

#### Feature - Output format
For geturl/ getfile - you can get your repsonse as a JSON, HTML or Print
simpley change the vt.out() to the desired output format and call the api normally. Exmaple:
```
vt.out('html')
vt.getfile('file.ext')

vt.out('print')
vt.geturl('http://github.com/nu11p0inter/')

vt.out('json')
...
```

## Author
```
Tal Melamed 
<github@appsec.it>
https://github.com/nu11p0inter/
```

### License
By using the scan API, you consent to virustotal [Terms of Service](https://www.virustotal.com/en/about/terms-of-service/)
and allow VirusTotal to share this file with the security community. See virustotal [Privacy Policy](https://www.virustotal.com/en/about/privacy/) for details.
