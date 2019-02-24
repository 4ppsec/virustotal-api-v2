![virustotal Logo](https://i.imgur.com/hD1oo3j.png)

API v2
==========
Python scripts to interact with the virustotal.com [Public API](https://www.virustotal.com/en/documentation/public-api/)


## Bash
```
usage: vt.py [-h] [-k] [-sk SETKEY] [-gf GETFILE] [-gu GETURL]
                   [-gi GETIP] [-gd GETDOMAIN] [-c COMMENT COMMENT]
                   [-sf SCANFILE] [-su SCANURL] [-r RESCAN] [-b BEHAVIOUR]
                   [-uf URLFEED] [-nt NETWORK] [-fs FILESEARCH] [-dl DOWNLOAD]
                   [-o OUTPUT] [-q] [-nb]

optional arguments:
  -h,  --help                                      | show this help message and exit
  -k,  --getkey                                    | print your VirusTotal API Key
  -sk, --setkey     [api_key]                      | set VirusTotal API Key
  -gf, --getfile    [options: path/to/file, md5]   | return result of the specified file
  -gu, --geturl     [url]                          | return result for the specified url
  -gi, --getip      [ip_address]                   | return result for the specified IP address
  -gd, --getdomain  [domain]                       | return result for the specified
  -c,  --comment    [resource] [comment]           | comment on a specified resource (hash)
  -sf, --scanfile   [options: path/to/file, md5]   | return result for the specified file
  -su, --scanurl    [url]                          | submit the specified url for a scan
  -r,  --rescan     [options: /path/to/file, hash] | request newscan for
  -b,  --behaviour  [options: /path/to/file, hash] | request dynamic behavioural report [Private API]
  -uf, --urlfeed    [package]                      | request received items for time window [Private API]
  -nt, --network    [options: /path/to/file, hash] | request traffic dump for file [Private API]
  -fs, --filesearch [options: /path/to/file, hash] | request file search [Private API]
  -dl, --download   [options: /path/to/file, hash] | download file [Private API]
  -o,  --output     [options: stdout, html, json]  | set the result output type. default=json
  -q,  --quiet                                     | when set, no prints to stdout  
  -nb, --nobrowser                                 | when using `html` mode, will disable automatic open of report
```

## python

#### Installation
 `pip install virustotal-api-v2`
 https://pypi.org/project/virustotal-api-v2/

#### Usage
```
# import
from vt import VT
vt = VT()

# key management
vt.getkey()
vt.setkey('___KEY___')


# API calls: FILES
vt.getfile('path/to/filename.ext')
vt.getfile('ee0fc30726c6dc1ef9ed15809c58d2bb438456ab')
vt.scanfile('path/to/file.ext')
vt.rescan('file.ext')
vt.rescan('ee0fc30726c6dc1ef9ed15809c58d2bb438456ab')

# API calls: NET
vt.geturl('https://github.com/nu11p0inter/')
vt.scanurl('http://github.com/nu11p0inter.com')
vt.getip('98.76.54.32')
vt.getdomain('github.com')

# API Call: Comment
hash = open(file, 'rb').read()
msg = "#Malware @https://github.com/nu11p0inter/virustotal/"
vt.comment(hash, msg)
vt.comment('path/to/filename.ext', msg)


# Set OUTPUT method:
vt.out('html')
vt.out('print')
vt.out('json')
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
