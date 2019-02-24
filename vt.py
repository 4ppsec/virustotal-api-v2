#!/usr/bin/env python

#
# A virustotal.com Public API interactiong script
# Copyright (C) 2015, Tal Melamed <virustotal AT appsec.it>
# Contribute @ https://github.com/nu11p0inter/virustotal/
#
# VT SCAN EULA
# ------------
# By using the upload/ scan API, you consent to virustotal
# Terms of Service (https://www.virustotal.com/en/about/terms-of-service/)
# and allow VirusTotal to share this file with the security community. 
# See virustotal Privacy Policy (https://www.virustotal.com/en/about/privacy/) for details.
#

import hashlib
import json
import os
import argparse
import requests
import ntpath
from os.path import expanduser

CONFIG_FILE = '.vt-config.json'
CONFIG_FOLDER = expanduser("~/")

DISABLE_PRINTS = True
DISABLE_BROWSER_OPEN = False
API_KEY = ''
API_URL = 'https://www.virustotal.com/vtapi/v2/'
OUTPUT = 'json'


class VT:

    # sets global variable
    def setglobals(self, glob, key):
        if glob == 'KEY':
            global API_KEY
            API_KEY = key
            return API_KEY

        elif glob == 'OUT':
            global OUTPUT
            OUTPUT = key
            return OUTPUT

        elif glob == 'API':
            global API_URL
            API_URL = key
            return API_URL

        elif glob == "QUT":
            global DISABLE_PRINTS
            DISABLE_PRINTS = key
            return DISABLE_PRINTS

        elif glob == "NOB":
            global DISABLE_BROWSER_OPEN
            DISABLE_BROWSER_OPEN = key
            return DISABLE_BROWSER_OPEN

        else:
            return

    # loads configuration
    def init(self):
        filepath = CONFIG_FOLDER + CONFIG_FILE
        if os.path.isfile(filepath) and os.path.getsize(filepath) > 0:
            with open(filepath) as file:
                conf = json.loads(file.read())
                self.setglobals('KEY', conf['api_key'])
                self.setglobals('OUT', conf['output'])
                self.setglobals('API', conf['api_url'])
        else:
            init_conf = {
                'api_key': '__YOUR_API_KEY_HERE__ (please set key)',
                'api_url': 'https://www.virustotal.com/vtapi/v2/',
                'output': 'json'
            }
            f = open(filepath, 'w+')
            f.write(json.dumps(init_conf))
            f.close()
            print("Thank you for using virustotal <virustotal[AT]appsec[DOT]it>\n"
                  "Contribute @ https://github.com/nu11p0inter/virustotal")
        return

    # set a new api-key
    def setkey(self, key):
        self.setglobals('KEY', key)
        filepath = CONFIG_FOLDER + CONFIG_FILE
        with open(filepath) as file:
            conf = json.loads(file.read())
            conf['api_key'] = key
            f = open(filepath, 'w')
            f.write(json.dumps(conf))
            f.close()
        if not DISABLE_PRINTS:
            print('Key was set to: {}...{}'.format(key[0:4], key[len(key)-4:]))
        return

    # prints api-key
    def getkey(self):
        if len(API_KEY) > 1 and API_KEY != '__YOUR_API_KEY_HERE__ (please set key)':
            if not DISABLE_PRINTS:
                print(API_KEY)
            return API_KEY
        else:
            print('API KEY was not set. Please use --setkey or --help for more info.')
            return -1

    # change mode of output - json, html or print to output
    def out(self, xformat):
        self.setglobals('OUT', xformat)
        filepath = CONFIG_FOLDER + CONFIG_FILE
        with open(filepath) as file:
            conf = json.loads(file.read())
            conf['output'] = xformat
            f = open(filepath, 'w')
            f.write(json.dumps(conf))
            f.close()
        if not DISABLE_PRINTS:
            print('output format was set to `{}`.'.format(str(xformat)))
        return xformat

    # make api calls
    def apicall(self, method, api, files=None, params=None):
        url = API_URL + api
        try:
            if method == "GET":
                r = requests.post(url, files=files, params=params)
            elif method == "POST":
                r = requests.get(url, files=files, params=params)
            else:
                return -1

            if r.status_code == 200:
                xjson = r.json()
                return self.report(xjson)
            else:
                return self.handle_http_erros(r.status_code)

        except Exception:
            if not DISABLE_PRINTS:
                print("Unknown error.")
            return -1

    # handles http error codes from vt
    def handle_http_erros(self, code):
        if code == 404:
            if not DISABLE_PRINTS:
                print('[Error 404] Something went wrong.')
            return 404

        elif code == 403:
            if not DISABLE_PRINTS:
                print('[Error 403] The api-key you are using, does not have permissions to make that call.')
            return 403

        elif code == 204:
            if not DISABLE_PRINTS:
                print('[Error 204] The quota limit has exceeded, please wait and try again soon.')
            return 204

        elif code == 400:
            if not DISABLE_PRINTS:
                print('Bad request. Your request was somehow incorrect.')
            return 400

        else:
            if not DISABLE_PRINTS:
                print('Unkown error.')
            return code

    # Sending and scanning files (-sf --scanfile)
    def scanfile(self, file):
        api = "file/scan"
        files = {'file': (ntpath.basename(file), open(file, 'rb'))}
        params = {"apikey": API_KEY}
        return self.apicall("GET", api, files=files, params=params)

    # scan url (-su --scanurl)
    def scanurl(self, link):
        api = "url/scan"
        params = {"url": link, "apikey": API_KEY}
        return self.apicall("GET", api, params=params)

    # get file (-gf --getfile)
    def getfile(self, file):
        if os.path.isfile(file):
            f = open(file, 'rb')
            file = hashlib.sha256(f.read()).hexdigest()
            f.close()
        api = "file/report"
        params = {"resource": file, "apikey": API_KEY}
        return self.apicall("GET", api, params=params)

    # get url (-gu --geturl)
    def geturl(self, resource):
        api = "url/report"
        params = {"resource": resource, "apikey": API_KEY}
        return self.apicall("GET", api, params=params)

    # get ip address
    def getip(self, ip):
        api = "ip-address/report"
        params = {"ip": ip, "apikey": API_KEY}
        return self.apicall("POST", api, params=params)

    # get domain
    def getdomain(self, domain):
        api = "domain/report"
        params = {"domain": domain, "apikey": API_KEY}
        return self.apicall("POST", api, params=params)

    # comment
    def comment(self, resource, add_comment):
        if os.path.isfile(resource):
            f = open(resource, 'rb')
            resource = hashlib.sha256(f.read()).hexdigest()
            f.close()
        api = "comments/put"
        params = {"resource": resource, "comment": add_comment, "apikey": API_KEY}
        return self.apicall("GET", api, params=params)

    # Rescanning already submitted files
    def rescan(self, resource):
        if os.path.isfile(resource):
            f = open(resource, 'rb')
            resource = hashlib.sha256(f.read()).hexdigest()
            f.close()
        api = "file/rescan"
        params = {"resource": resource, "apikey": API_KEY}
        return self.apicall("POST", api, params=params)

    # behaviour (-b --behaviour)
    def behaviour(self, resource):
        if os.path.isfile(resource):
            f = open(resource, 'rb')
            resource = hashlib.sha256(f.read()).hexdigest()
            f.close()
        api = "file/behaviour"
        params = {'hash': resource, "apikey": API_KEY}
        return self.apicall("POST", api, params=params)

    # available only for getfile and geturl
    def report(self, jsonx):
        if OUTPUT == 'html':
            url = jsonx.get('permalink')
            if not DISABLE_PRINTS:
                print(url)
            r = requests.get(url)
            html = r.text
            html = html.replace('<div class="frame" style="margin:20px 0">',
                                '<a href="https://github.com/nu11p0inter/virustotal">Created by git[AT]appsec[DOT]it</a><div class="frame" style="margin:20px 0">')

            f = open("report.html", 'w+')
            f.write(html.encode('utf-8'))
            f.close()
            if not DISABLE_BROWSER_OPEN:
                import webbrowser
                webbrowser.open('file://' + os.path.realpath('report.html'))

        elif OUTPUT == 'stdout':
            for key, value in jsonx.iteritems():
                if key == 'total':
                    total = value
                    continue

                if key == 'positives':
                    pos = value
                    continue

                if key == "scans":
                    print('total: {}/{} (positives)'.format(str(pos), str(total)))
                    if int(pos) > 0:
                        print('\npositive_results:\n-----------------')
                        for av, res in value.iteritems():
                            if res['detected']:
                                print('{}: {}'.format(av, res['result']))
                else:
                    print('{}: {}'.format(key,value))

        else:
            if not DISABLE_PRINTS:
                print(json.dumps(jsonx))
            return jsonx


def main():
    vt = VT()
    vt.init()

    parser = argparse.ArgumentParser()
    parser.add_argument("-k",  "--getkey", required=False, default=None, action="store_true",
                        help="print your VirusTotal API Key")

    parser.add_argument("-sk", "--setkey", required=False, default=None,
                        help="options: [api_key] | set VirusTotal API Key")

    parser.add_argument("-gf", "--getfile", required=False, default=None,
                        help="options: [path/to/file] [md5] | return result of the specified file")

    parser.add_argument("-gu", "--geturl", required=False, default=None,
                        help="options: [url] | return result for the specified url")

    parser.add_argument("-gi", "--getip", required=False, default=None,
                        help="options: [ip_address] | return result for the specified IP address")

    parser.add_argument("-gd", "--getdomain", required=False, default=None,
                        help="options: [domain] | return result for the specified domain")

    parser.add_argument("-c",  "--comment", required=False, nargs=2, default=None,
                        help="options: [md5 your_comment] | comment on a specified resource (hash)")

    parser.add_argument("-sf", "--scanfile", required=False, default=None,
                        help="options: [domain] | return result for the specified domain")

    parser.add_argument("-su", "--scanurl", required=False, default=None,
                        help="options: [url] | submit the specified url for a scan")

    parser.add_argument("-r",  "--rescan", required=False, default=None,
                        help="options: [/path/to/file] [hash] | request newscan for a resource (file/hash)")

    parser.add_argument("-b", "--behaviour", required=False, default=None,
                        help="options: [/path/to/file] [hash] | request dynamic behavioural report [Private API]")

    parser.add_argument("-uf", "--urlfeed", required=False, default=None,
                        help="options: [/path/to/file] [hash] | request received items for time window [Private API]")

    parser.add_argument("-nt", "--network", required=False, default=None,
                        help="options: [/path/to/file] [hash] | request traffic dump for file [Private API]")

    parser.add_argument("-fs", "--filesearch", required=False, default=None,
                        help="options: [/path/to/file] [hash] | request file search [Private API]")

    parser.add_argument("-dl", "--download", required=False, default=None,
                        help="options: [/path/to/file] [hash] | download file [Private API]")

    parser.add_argument("-o",  "--output", required=False, default=None,
                        help="options: [stdout] [html] [json] | set the result output type, default=json")

    parser.add_argument("-q",  "--quiet", required=False, default=False, action="store_true",
                        help="verbose mode")

    parser.add_argument("-nb", "--nobrowser", required=False, default=False, action="store_true",
                        help="when using `html` mode, will disable automatic open of report")

    args = parser.parse_args()

    vt.setglobals("QUT", args.quiet)

    if args.nobrowser:
        vt.setglobals("NOB", args.nobrowser)

    if args.setkey is not None:
        vt.setkey(args.setkey)
        return

    elif args.getkey is not None:
        vt.getkey()
        return

    elif args.output is not None:
        vt.out(args.output)
        return

    elif args.getfile is not None:
        vt.getfile(args.getfile)
        return

    elif args.geturl is not None:
        vt.geturl(args.geturl)
        return

    elif args.getip is not None:
        vt.getip(args.getip)
        return

    elif args.getdomain is not None:
        vt.getdomain(args.getdomain)
        return

    elif args.scanfile is not None:
        vt.scanfile(args.scanfile)
        return

    elif args.scanurl is not None:
        vt.scanurl(args.scanurl)
        return

    elif args.urlfeed is not None:
        #vt.urlfeed(args.urlfeed)
        if not DISABLE_PRINTS:
            print("Not implemented yet.")
        return -1

    elif args.filesearch is not None:
        #vt.filesearch(args.filesearch)
        if not DISABLE_PRINTS:
            print("Not implemented yet.")
        return -1

    elif args.download is not None:
        #vt.download(args.download)
        if not DISABLE_PRINTS:
            print("Not implemented yet.")
        return -1

    elif args.network is not None:
        #vt.network(args.network)
        if not DISABLE_PRINTS:
            print("Not implemented yet.")
        return -1

    elif args.rescan is not None:
        vt.rescan(args.rescan)
        return

    elif args.behaviour is not None:
        vt.behaviour(args.behaviour)
        return

    elif args.comment is not None:
        vt.comment(args.comment[0], args.comment[1])
        return

    else:
        return 0


if __name__ == "__main__":
    main()

