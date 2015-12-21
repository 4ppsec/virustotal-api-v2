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

import hashlib, urllib, urllib2, json, os
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

    # change mode of output - json, html or print to output
    def out(self, xformat):
        if xformat == "print":
            self._output = "print"
        elif xformat == "html":
            self._output = "html"
        else:
            self._output = "json"
            
    # Sending and scanning files
    def filescan(self, file):
        url = self.api_url + "file/scan"
        files = {'file': open(file, 'rb')}
        headers = {"apikey": self.api_key}
        try:
            response = requests.post( url, files=files, data=headers )
            xjson = response.json()
            response_code = xjson ['response_code']
            verbose_msg = xjson ['verbose_msg']
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()           

    # Sending and scanning URLs
    def urlscan(self, link):
        url = self.api_url + "url/scan"
        parameters = {"url": link, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
        
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc() 
        
    
    # Retrieving file scan reports
    def getfile(self, file):
        if os.path.isfile(file):
            f = open(file, 'rb')
            file = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "file/report"
        parameters = {"resource": file, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return report(xjson)
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()       
              
    # Retrieving URL scan reports
    def geturl(self, resource):
        url = self.api_url + "url/report" 
        parameters = {"resource": resource, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
        
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()
            
    #Retrieving IP address reports
    def getip (self, ip):
        url = self.api_url + "ip-address/report"
        parameters = {"ip": ip, "apikey": self.api_key}
        try:
            response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
            xjson = json.loads(response)
            response_code = xjson['response_code']
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()  
        
    # Retrieving domain reports
    def getdomain(self, domain):
        url = self.api_url + "domain/report"
        parameters = {"domain": domain, "apikey": self.api_key}
        try:
            response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
            xjson = json.loads(response)
            response_code = xjson['response_code']
            if response_code == 1:
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()  
        
    # Make comments on files and URLs
    def comment(self, resource, comment):
        if os.path.isfile(resource):
            f = open(resource, 'rb')
            resource = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "comments/put"
        parameters = {"resource": resource, "comment": comment, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()    
    #Rescanning already submitted files  
    def rescan(self, resource):
        if os.path.isfile(resource):
            f = open(resource, 'rb')
            resource = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "file/rescan"
        parameters = {"resource":  resource, "apikey": self.api_key }
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()

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
    def report(self, json):
        if self._output == "json":
            return result

        elif self._output == "html":
            if xtype == "ip-address" or xtype == "domain":
                print "https://www.virustotal.com/en/" + xtype + "/" + xresource + "/information/"
                # todo: get html results for ip/domain
                return json
            else:
                url = result.get('permalink')
                print url
                html = urllib2.urlopen(url, timeout=3).read()
                return html.replace('<div class="frame" style="margin:20px 0">', '<a href="https://github.com/nu11p0inter/virustotal"> Exceuted by Tal Melamed [virustotal@appsec.it]</a> <div class="frame" style="margin:20px 0">')
        else: #print
            if xtype == "ip-address" or xtype == "domain":
                #todo: parse results for ip/domain
                return json
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
