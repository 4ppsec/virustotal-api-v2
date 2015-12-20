#!/usr/bin/env python

#
# A virustotal.com Public API interactiong script
# Copyright (C) 2015, Tal Melamed <virustotal AT appsec.it>
#
# VT SCAN EULA
# ------------
# By using the upload/ scan API, you consent to virustotal
# Terms of Service (https://www.virustotal.com/en/about/terms-of-service/)
# and allow VirusTotal to share this file with the security community. 
# See virustotal Privacy Policy (https://www.virustotal.com/en/about/privacy/) for details.
#

import sys, os, select, imp, re, urlparse
import hashlib, urllib, urllib2, json
try:
    import requests
except:
    print '[Warning] request module is missing. requests module is required in order to upload new files for scan.\nYou can install it by running: pip install requests.'

class vt:
    def __init__(self):
        self.api_key = '84a3beb16d1824c097a0924e10e6ad394938e1573cd87d9481a20b56e658d554' #'< YOUR API KEY HERE >'
        self.api_url = 'https://www.virustotal.com/vtapi/v2/'
        # default ouput format --> print to output
        # print, json, html
        self._output = "json"
        # default mode --> get report
        # report, scan, rescan, comment
        self._mode = "report"
        self.errmsg = 'Something went wrong. Please try again later, or contact us.'
        print "Thank you for using virustotal by Tal Melamed <virustotal@appsec.it>\nContribute @ https://github.com/nu11p0inter/virustotal"

    # handles http error codes from vt
    def handleHTTPErros(self, code):
        if code == 404:
            print self.errmsg + '\n[Error 404].'
            return 0
        elif code == 403:
            print 'You do not have permissions to make that call.\nThat should not have happened, please contact us.\n[Error 403].'
            return 0
        elif code == 204:
            print 'The quota limit has exceeded, please wait and try again soon.\nIf this problem continues, please contact us.\n[Error 204].'
            return 0
        else:
            print self.errmsg + '\n[Error '+str(code)+']'
            return 0
        
    # change mode of api - scan/rescan, report or comment

    def mode(self, xmode):
        if xmode == "scan":
            self._mode = "scan"
        elif xmode == "rescan":
            self._mode = "rescan"
        elif xmode == "comment":
            self._mode = "comment"
        else:
            self._mode = "report"

    # change mode of output - json, html or print to output
    def out(self, xformat):
        if xformat == "print":
            self._output = "print"
        elif xformat == "html":
            self._output = "html"
        else:
            self._output = "json"


    # retreive/scan URL
    def url(self, xurl):
        return self.get("url", xurl)

        
    # retreive/rescan file's hash
    def hash(self, xhash):
        return self.get("hash", xhash)
            
    # retreive/rescan file 
    def file(self, xfile):
        return self.get("file", xfile)

    # retreive/rescan domain   
    def domain(self, xdomain):
        return self.get("domain", xdomain) 
    # retreive/rescan ip 
    def ip(self, xip):
        return self.get("ip-address", xip)
    

    # internal - mode REPORT
    def get(self, xtype, xresource):
        resource = "resource"
        if xtype == "url":
            api_addr  = self.api_url + xtype + "/" + self._mode
            resource = "resource"
            
        elif xtype == "domain":
            resource = "domain"
            api_addr  = self.api_url + xtype + "/" + self._mode
            
        elif xtype == "ip-address":
            api_addr  = self.api_url + xtype + "/" + self._mode
            resource = "ip"
            
        elif xtype == "file":
            api_addr  = self.api_url + xtype + "/" + self._mode
            f = open(xresource, 'rb').read()
            xresource = hashlib.sha256(f).hexdigest()
            
        elif xtype == "hash":
            api_addr  = self.api_url + "file" + "/" + self._mode

        else:
            return -1

        parameters = {resource: xresource, "apikey": self.api_key }
        try:
            response = urllib.urlopen('%s?%s' % (api_addr, urllib.urlencode(parameters))).read()
            try:
                xjson = json.loads(response)
                response_code = xjson.get('response_code')
            except:
                data = urllib.urlencode(parameters)
                req = urllib2.Request(api_addr, data)
                response = urllib2.urlopen(req)
                xjson = response.read()
                print xjson
                response_code = 0
            #response_msg = xjson.get('verbose_msg')
            if response_code == 0:
                print "No information was found on resource: " + xresource + "\nRun: # vt.mode('scan') to change to 'scan' mode and execute again."
                return 0
            # the file is already in queue for scanning
            elif response_code == -2:
                print 'The requested file was already sent for scanning.\nPlease try again later for the results.'
                return -2
            # results were found for file
            elif response_code == 1:
                #print 'Found results for resource: ' + xresource + ':\n'
                return self.results(xjson, xtype, xresource)
            # unknown reponse from VT...   
            else:
                print self.errmsg +'\nUnexpected response: [response_code: ' + response_code + ']'
                return -1

        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()
            
    # internal - returns results accourding to output format (json, html or output)
    def results(self, result, xtype, xresource):
        if self._output == "json":
            return result

        elif self._output == "html":
            if xtype == "ip-address" or xtype == "domain":
                # no url in api for ip/domain
                return "https://www.virustotal.com/en/" + xtype + "/" + xresource + "/information/"
            else:
                url = result.get('permalink')
                print url
                html = urllib2.urlopen(url, timeout=3).read()
                return html.replace('<div class="frame" style="margin:20px 0">', '<a href="https://github.com/nu11p0inter/virustotal"> Exceuted by Tal Melamed [virustotal@appsec.it]</a> <div class="frame" style="margin:20px 0">')
        else:
            if xtype == "ip-address" or xtype == "domain":
                pass
                #todo: parse result
            else:
                avlist = []
                scan_date = result.get('scan_date')
                total = result.get('total')
                positive = result.get('positives')
                print 'Scan date: ' + scan_date
                print 'Detection ratio: ' + str(positive) + "/" + str(total)
                scans = result.get('scans')
                for av in scans.iterkeys():
                    res = scans.get(av)
                    if res.get('detected') == True:
                        avlist.append('+ ' + av + ':  ' + res.get('result'))
                if positive > 0:
                    for res in avlist:
                        print res
                    return avlist
                else:
                    return 0


    # set a new api-key
    def setkey(self, key):
        self.api_key = key
    # get current status    
    def status(self):
        print "key: " + self.api_key
        print "api: " + self.api_url
        print "mode: " + self._mode
        print "output: " + self._output
        
