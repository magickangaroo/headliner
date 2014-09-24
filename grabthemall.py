__author__ = 'adz'
import requests
import json
import time
import argparse
import socket

def hostname_resolves(hostname):
    #http://stackoverflow.com/questions/11618118/python-check-if-a-hostname-is-resolved
    try:
        socket.gethostbyname(hostname)
        return 1
    except socket.error:
        return 0

def analyseheaders(url, headers):
    #headerstolookfor = ["x-xss-protection", "cache-control", "x-frame-options", "Strict-Transport-Security",
    #                    "X-Content-Type-Options"]
    #Ommiting cache control as need to tweak, but does show how you compare a header value to see if its expected
    headerstolookfor = ["x-xss-protection", "x-frame-options", "Strict-Transport-Security", "X-Content-Type-Options"]
    headersnotfound = []
    headerswithproblems = []
    for header in headerstolookfor:
        if header not in headers:
            #print "[!] Header not found in request : %s" % header
            headersnotfound.append(header)
        elif header in headers:
            #print "[i] Found this intersting header %s with this value %s" % (header, headers[header])
            if header == "cache-control" and headers[header] != "private, max-age=1":
                #print "[!] Cache control header not set correctly"
                headerswithproblems.append("Cache control header not set correctly")

    returnvalue = [url, headersnotfound, headerswithproblems]
    return returnvalue

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbosity", help="increase output verbosity")
    parser.add_argument("-p", "--proxy", help="proxy to use eg : 127.0.0.1:8080")
    parser.add_argument("-u", "--urls", help="url listing")
    args = parser.parse_args()
    results = []
    errors = []
    with open(args.urls, 'r') as f:
        urls = [line.rstrip() for line in f]

    print "[*] Found %i Urls" % len(urls)

    for url in urls:

        if args.proxy != None:
            proxydict = {
                "http": "http://" + args.proxy,
                "https": "http://" + args.proxy
            }

        r = None
        if "https" in url:
            #dont want to choke on ssl issues
            if args.proxy != None:
                try:
                    r = requests.get(url, proxies=proxydict, verify=False)
                except:
                    errors.append("[E] Error with %s" % url)
            else:
                try:
                    r = requests.get(url, verify=False)
                except:
                    errors.append("[E] Error with %s" % url)

        else:
            if args.proxy != None:
                try:
                    r = requests.get(url, proxies=proxydict)
                except:
                    errors.append("[E] Error with %s" % url)
            else:
                try:
                    r = requests.get(url)
                except:
                    errors.append("[E] Error with %s" % url)
        if r == None:
            continue
        else:
            #print "[i] looking at headers found at the following url : %s" % url
            #sending the url and headers to be analysied, will retunr a list which is appended to results
            results.append(analyseheaders(url, r.headers))
            #print "------======------"

        #print "------======------"
    print "Summary Below"
    print "------======------"
    for result in results:
        print "***\n[R] URL checked was %s" % (result[0])
        if len(result[1]) > 0:
            print "\n[R] Missing headers were %s" % str(result[1])
        if len(result[2]) > 0:
            print "\n[R] headers with problems wer %s" % str(result[2])
        if len(result[1]) == 0 and len(result[2]) == 0:
            print "\n[R] No problems found!"



    print "------======------"
    print "[E] The following hosts had errors"
    for error in errors:
        print error

if __name__ == "__main__":
    main()