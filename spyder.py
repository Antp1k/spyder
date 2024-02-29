#!/usr/bin/python3

import argparse
import requests
import random
import re
import time
import concurrent.futures
from termcolor import colored as clr

"""
This tool is a web spider designed to gather endpoints in depth of 1 and put all of those results into a list.
Endpoints in this list are then going to be further checked for JS files, parameters and so on.
"""

### PARSER
p = argparse.ArgumentParser()
p.add_argument(
        '-l',
        '--list',
        dest="list",
        required=True,
        help="List of target domains."
        )
p.add_argument(
        '-v',
        '--verbose',
        dest="verb",
        action="store_true",
        help="Print error messages, if they occur."
        )
p.add_argument(
        '-t',
        '--target',
        dest="targets",
        required=True,
        help="Give targets separated by comma i.e: twitter,twimg"
        )
p.add_argument(
        '-c',
        '--cookies',
        dest="cookies",
        default=False,
        help="Pass cookies i.e: 'Auth=value Cookie=value'."
        )
p.add_argument(
        '-H',
        '--header',
        dest="header",
        default=False,
        help="Pass a header i.e: 'Authorization:Bearer value'."
        )
p.add_argument(
        '-U',
        '--useragent',
        dest="useragent",
        default=False,
        help="Could be needed to bypass cloudflare."
        )
p.add_argument(
        '-i',
        '--ignore',
        dest="ignore",
        default=False,
        help="String that will be ignored. Useful when there is a LARGE JS file, that could break the tool."
        )
p.add_argument(
        '-t'
        '--threads',
        dest="threads",
        default=25,
        help="The amount of threads to use in the scan."
        )
args = p.parse_args()

### USER AGENTS
user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246", "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/99.0.1150.36", "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.6; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Linux i686; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34", "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34", "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"]

### FUNCTIONS
def user_agent_generator():
    return user_agents[random.randint(0,len(user_agents)-1)]

def reg_headers():
    #return {"User-Agent":user_agent_generator(),"Accept-Encoding":"gzip, deflate, br","Accept":"*/*","Accept-Language":"en-US,en;q=0.5"}
    return {"User-Agent":user_agent_generator(),"Accept":"*/*","Accept-Language":"en-US,en;q=0.5"}

def get_file(file):
    ls = []
    with open(file,"r") as f:
        for e in f:
            ls.append(e.rstrip())
    return ls

def clean_jslist(js_list):
    # Remove trash js files from a list of js files
    clean_js = []
    garbage = r"/[0-9]+[\-_\.]{1}[a-zA-Z0-9]+\.m?js"
    for j in js_list:
        if re.search(garbage,j) == None:
            for v in valid:
                if v in j:
                    if j not in clean_js:
                        clean_js.append(j)
    return clean_js

def strip_quotes(alist):
    # Strip " and ' from all lines
    clean_list = []
    for l in alist:
        if "\"" in l:
            r = l.strip("\"")
        else:
            r = l.strip("'")
        if r not in clean_list:
            clean_list.append(r)
    return clean_list

def get_request(domain):
    '''Make a get request to the "domain", and return it\'s contents.'''
    for _ in range(5):
        try:
            if args.cookies != False:
                r = requests.get(domain, headers=reg_headers(), allow_redirects=False, cookies=cookies, timeout=(10,20))
            else:
                r = requests.get(domain, headers=reg_headers(), allow_redirects=False, timeout=(10,20))
        except Exception:
            if args.verb:
                print("[",clr("ERR","red"),"]",domain,"connection error.","                    ",end="\r")
    try:
        if r == None:
            r = "None"
    except Exception:
        if args.verb:
            print("[",clr("ERR","red"),"]",domain,"returned 'None' value.")
        return "None"
    return r

def extract_links(text, dir_list, endpoint_list, jsfile_list):
    '''Extract dirs, JS files and endpoints from the response text.'''
    dir_re = r"(?<=[\"'])/[a-zA-Z\-_\./]+(?=[\"'])"
    endpoint_re = r"https?://[\w\.\-/]+/[a-zA-Z0-9/\-_]+"
    jsfile_re = r"https?://[\w\.\-]+/[a-zA-Z0-9/\.\-_]+\.m?js"

    found_dirs = re.findall(dir_re,text)
    found_eps = re.findall(endpoint_re,text)
    found_js = re.findall(jsfile_re,text)

    # Gotta strip " or ' from these
    #clean_dirs = strip_quotes(found_dirs)
    #clean_eps = strip_quotes(found_eps)
    clean_js = clean_jslist(found_js)

    # Adding results to current lists
    for d in found_dirs:
        if d not in dir_list:
            dir_list.append(d)
    for e in found_eps:
        for v in valid:
            if v in e:
                if e not in endpoint_list:
                    endpoint_list.append(e)
    for j in clean_js:
        if j not in jsfile_list:
            jsfile_list.append(j)
    
    return dir_list, endpoint_list, jsfile_list

### SCRIPT
if __name__ == "__main__":
    # Get list of domains
    doms = get_file(args.list)

    # Making a list of targets
    try:
        valid = args.targets.split(",")
    except Exception:
        valid = list(args.targets)

    # Cookies
    cookies = {}
    if args.cookies != False:
        a = args.cookies.split(" ")
        for x in a:
            b = x.split("=")
            if ";" in b[1]:
                b[1] = b[1].replace(";","")
            cookies.update({f"{b[0]}":f"{b[1]}"})

    # Ignore list
    if args.ignore != False:
        try:
            ignore = args.ignore.split(",")
        except Exception:
            ignore = list(args.ignore)

    # Vars, lists
    f_jsfiles = []
    s_jsfiles = []
    dirs = []
    eps = []
    final_doms = []
    output_endpoints = []

    # Mainly get JS files from targets
    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as exe:
        f1 = [exe.submit(get_request,doms[x]) for x in range(len(doms))]
        for comp in concurrent.futures.as_completed(f1):
            r = comp.result()
            count += 1
            try:
                if r.status_code == 200:
                    print("[",clr("?","yellow"),"]","[",clr(len(r.text),"magenta"),"]",r.url,"(",clr(f"{count}/{len(doms)}","green"),")","                    ",end="\r")
                    dirs, eps, f_jsfiles = extract_links(r.text,dirs,eps,f_jsfiles)
                elif r.status_code == 401 or r.status_code == 403 or r.status_code == 429:
                    print("[",clr("!","red"),"]",r.url,"Error!",clr(r.status_code,"red"),"                      ",end="\r")
            except Exception:
                pass

    print("\n[",clr("+","green"),"]","Found",clr(len(f_jsfiles),"magenta"),"JS files!")

    # Now check each JS file once
    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as exe:
        f1 = [exe.submit(get_request,f_jsfiles[x]) for x in range(len(f_jsfiles))]
        for comp in concurrent.futures.as_completed(f1):
            r = comp.result()
            count += 1
            try:
                if r.status_code == 200:
                    print("[",clr("?","yellow"),"]",r.url,"(",clr(f"{count}/{len(f_jsfiles)}","green"),")","                   ",end="\r")
                    dirs, eps, s_jsfiles = extract_links(r.text,dirs,eps,s_jsfiles)
                elif r.status_code == 401 or r.status_code == 403 or r.status_code == 429:
                    print("[",clr("!","red"),"]",r.url,"Error!",clr(r.status_code,"red"),"                        ",end="\r")
            except Exception:
                pass

    # From all dirs found in jsfiles, create a list of endpoints
    for d in doms:
        final_doms.append(d)
        for dr in dirs:
            if f"{d}{dr}" not in final_doms:
                final_doms.append(f"{d}{dr}")

    for e in eps:
        if e not in final_doms:
            final_doms.append(e)

    print("\n[",clr("+","green"),"]","Created",clr(len(final_doms),"magenta"),"domains!")

    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as exe:
        f1 = [exe.submit(get_request,final_doms[x]) for x in range(len(final_doms))]
        for comp in concurrent.futures.as_completed(f1):
            r = comp.result()
            count += 1
            try:
                if r.status_code == 200:
                    print("[",clr("?","yellow"),"]",r.url,"(",clr(f"{count}/{len(final_doms)}","green"),")","                    ",end="\r")
                    dirs, eps, s_jsfiles = extract_links(r.text,dirs,eps,s_jsfiles)
                    if r.url not in output_endpoints:
                        output_endpoints.append(f"{r.url} cl:{len(r.text)}")
                elif r.status_code == 401 or r.status_code == 403 or r.status_code == 429:
                    print("[",clr("!","red"),"]",r.url,"Error!",clr(r.status_code,"red"),"                      ",end="\r")
            except Exception:
                pass
            
    print("\n[",clr("+","green"),"]","Found",clr(len(output_endpoints),"magenta"),"live endpoints. \"spyder_endpoints.txt\" created!")

    with open("spyder_endpoints.txt","w") as f:
        for e in output_endpoints:
            f.write(f"{e}\n")

    print("\n[",clr("+","green"),"]","Found",clr(len(s_jsfiles),"magenta"),"JS files. \"spyder_js.txt\" created!")

    with open("spyder_js.txt","w") as f:
        for e in s_jsfiles:
            f.write(f"{e}\n")

    print("\n[",clr("+","green"),"]","Found",clr(len(dirs),"magenta"),"directories. \"spyder_dirs.txt\" created!")

    with open("spyder_dirs.txt","w") as f:
        for e in dirs:
            f.write(f"{e}\n")
