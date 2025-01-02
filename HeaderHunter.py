#!/usr/bin/env python3

import urllib.request
import urllib.error
import urllib.parse
import http.client
import socket
import sys
import ssl
import os
import json
from optparse import OptionParser

# This is a tool that was originally created by Santoru (# Copyright (C) 2019-2021  santoru)
# I made a few adjustments to the tool to make it more useful for me, with that said, all credits to him
# original tool: https://github.com/santoru/shcheck
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

class darkcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class lightcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[95m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log(string):
    if options.json_output:
        return
    print(string)

client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': 1
}

sec_headers = {
    'X-XSS-Protection': {
        'description': "Protects against cross-site scripting attacks by enabling or disabling XSS filtering in the browser.",
        'mitigation': "1; mode=block"
    },
    'X-Frame-Options': {
        'description': "Prevents the web page from being embedded into frames or iframes, mitigating clickjacking attacks.",
        'mitigation': "SAMEORIGIN"
    },
    'X-Content-Type-Options': {
        'description': "Prevents the browser from interpreting files as a different MIME type than what is specified.",
        'mitigation': "nosniff"
    },
    'Strict-Transport-Security': {
        'description': "Forces browsers to interact with the site only over HTTPS, mitigating man-in-the-middle attacks.",
        'mitigation': "max-age=31536000; includeSubDomains"
    },
    'Content-Security-Policy': {
        'description': "Defines approved sources of content for the browser to load, mitigating various injection attacks.",
        'mitigation': "default-src 'self';"
    },
    'X-Permitted-Cross-Domain-Policies': {
        'description': "Restricts Adobe Flash Player's access to data on a domain.",
        'mitigation': "none"
    },
    'Referrer-Policy': {
        'description': "Controls how much referrer information is included with requests made from the site.",
        'mitigation': "no-referrer"
    },
    'Expect-CT': {
        'description': "Allows sites to determine if they are being accessed via a misissued certificate.",
        'mitigation': "max-age=86400, enforce"
    },
    'Permissions-Policy': {
        'description': "Restricts the use of browser features like geolocation and camera access.",
        'mitigation': "geolocation=(), camera=()"
    },
    'Cross-Origin-Embedder-Policy': {
        'description': "Requires a secure embedding context, mitigating certain cross-origin attacks.",
        'mitigation': "require-corp"
    },
    'Cross-Origin-Resource-Policy': {
        'description': "Prevents resources from being shared with cross-origin contexts unless explicitly allowed.",
        'mitigation': "same-origin"
    },
    'Cross-Origin-Opener-Policy': {
        'description': "Isolates browsing contexts to prevent cross-origin information leaks.",
        'mitigation': "same-origin"
    }
}

headers = {}

def banner():
    log("")
    log("======================================================")
    log(" > HeaderHunter - TrK ................................")
    log("------------------------------------------------------")
    log(" Simple tool to check security headers on a webserver ")
    log("======================================================")
    log("")

def colorize(string, alert):
    bcolors = darkcolours
    if options.colours == "light":
        bcolors = lightcolours
    elif options.colours == "none":
        return string
    color = {
        'error':    bcolors.FAIL + string + bcolors.ENDC,
        'warning':  bcolors.WARNING + string + bcolors.ENDC,
        'ok':       bcolors.OKGREEN + string + bcolors.ENDC,
        'info':     bcolors.OKBLUE + string + bcolors.ENDC,
        'deprecated': string
    }
    return color[alert] if alert in color else string

def parse_headers(hdrs):
    global headers
    headers = dict((x.lower(), y) for x, y in hdrs)

def append_port(target, port):
    return target[:-1] + ':' + port + '/' if target[-1:] == '/' else target + ':' + port + '/'

def build_opener(proxy, ssldisabled):
    proxyhnd = urllib.request.ProxyHandler()
    sslhnd = urllib.request.HTTPSHandler()
    if proxy:
        proxyhnd = urllib.request.ProxyHandler({'http': proxy, 'https': proxy})
    if ssldisabled:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sslhnd = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(proxyhnd, sslhnd)
    urllib.request.install_opener(opener)

def normalize(target):
    try:
        if socket.inet_aton(target):
            target = 'http://' + target
    except (ValueError, socket.error):
        pass
    finally:
        return target

def print_error(target, e):
    sys.stdout = sys.__stdout__
    if isinstance(e, ValueError):
        print("Unknown url type")
    elif isinstance(e, urllib.error.HTTPError):
        print("[!] URL Returned an HTTP error: {}".format(colorize(str(e.code), 'error')))
    elif isinstance(e, urllib.error.URLError):
        if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
            print("SSL: Certificate validation error.\nIf you want to ignore it run the program with the \"-d\" option.")
        else:
            print("Target host {} seems to be unreachable ({})".format(target, e.reason))
    else:
        print("{}".format(str(e)))

def check_target(target):
    ssldisabled = options.ssldisabled
    useget = options.useget
    usemethod = options.usemethod
    proxy = options.proxy
    response = None
    target = normalize(target)
    request = urllib.request.Request(target, headers=client_headers)
    method = "GET" if useget else usemethod
    request.get_method = lambda: method
    build_opener(proxy, ssldisabled)
    try:
        response = urllib.request.urlopen(request, timeout=10)
    except http.client.UnknownProtocol as e:
        print("Unknown protocol: {}. Are you using a proxy? Try disabling it".format(e))
    except Exception as e:
        print_error(target, e)
        if hasattr(e, 'code') and e.code >= 400 and e.code < 500:
            response = e
        else:
            return None
    if response is not None:
        return response
    print("Couldn't read a response from server.")
    return None

def is_https(target):
    return target.startswith('https://')

def report(target, safe, unsafe):
    log("-------------------------------------------------------")
    log(f"\n{darkcolours.BOLD}{darkcolours.OKBLUE}[!] Headers analyzed for {target}{darkcolours.ENDC}\n")
    log(f"{darkcolours.BOLD}{darkcolours.OKGREEN}[+] There are {safe} security headers{darkcolours.ENDC}")
    log(f"{darkcolours.BOLD}{darkcolours.FAIL}[-] There are {unsafe} missing security headers{darkcolours.ENDC}\n")

def parse_csp(csp):
    unsafe_operators = ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes', 'wasm-unsafe-eval', 'self']
    log(f"\n{darkcolours.BOLD}Content Security Policy Details:{darkcolours.ENDC}\n")
    policy_directive = csp.split(";")
    for policy in policy_directive:
        elements = policy.lstrip().split(" ", 1)
        values = elements[1].replace("*", colorize("*", 'warning')) if len(elements) > 1 else ""
        for x in unsafe_operators:
            values = values.replace(x, colorize(x, 'error'))
        log(f"{darkcolours.OKBLUE}{elements[0]}:{darkcolours.ENDC} {values}\n")

def main():
    global options
    options, targets = parse_options()
    port = options.port
    cookie = options.cookie
    custom_headers = options.custom_headers
    hfile = options.hfile
    json_output = options.json_output

    if not targets and not hfile:
        print(f"{darkcolours.FAIL}Error: No targets or header file provided. Please specify a target or header file.{darkcolours.ENDC}")
        sys.exit(1)

    if json_output:
        global json_headers
        sys.stdout = open(os.devnull, 'w')
    banner()
    if cookie is not None:
        client_headers.update({'Cookie': cookie})
    if custom_headers is not None:
        for header in custom_headers:
            header_split = header.split(': ')
            try:
                client_headers.update({header_split[0]: header_split[1]})
            except IndexError:
                s = f"{darkcolours.FAIL}[!] Header strings must be of the format 'Header: value'{darkcolours.ENDC}"
                print(s)
                raise SystemExit(1)
    if hfile is not None:
        with open(hfile) as f:
            targets = f.read().splitlines()
    json_out = {}
    for target in targets:
        json_headers = {}
        if port is not None:
            target = append_port(target, port)
        safe = 0
        unsafe = 0
        log(f"\n{darkcolours.BOLD}[*] Analyzing headers of {target}{darkcolours.ENDC}\n")
        response = check_target(target)
        if not response:
            continue
        rUrl = response.geturl()
        json_results = {}
        log(f"\n{darkcolours.BOLD}[*] Effective URL: {rUrl}{darkcolours.ENDC}\n")
        parse_headers(response.getheaders())
        json_headers[f"{rUrl}"] = json_results
        json_results["present"] = {}
        json_results["missing"] = []
        for header, details in sec_headers.items():
            lheader = header.lower()
            if lheader in headers:
                safe += 1
                json_results["present"][header] = {
                    "value": headers.get(lheader),
                    "description": details['description'],
                    "mitigation": details['mitigation'],
                    "scope": rUrl,
                    "finding_type": "Present Header"
                }
                log(f"\n{darkcolours.BOLD}{darkcolours.OKGREEN}[*] Header {header} is present!{darkcolours.ENDC}\n{darkcolours.OKBLUE}  Description:{darkcolours.ENDC} {details['description']}\n{darkcolours.OKGREEN}  Recommended Value:{darkcolours.ENDC} {details['mitigation']}\n{darkcolours.OKBLUE}  Current Value:{darkcolours.ENDC} {headers.get(lheader)}\n{darkcolours.OKBLUE}  Scope:{darkcolours.ENDC} {rUrl}\n{darkcolours.OKBLUE}  Finding Type:{darkcolours.ENDC} Present Header\n")
                log(f"{darkcolours.WARNING}**************************************************{darkcolours.ENDC}")
            else:
                unsafe += 1
                json_results["missing"].append({
                    "header": header,
                    "description": details['description'],
                    "mitigation": details['mitigation'],
                    "scope": rUrl,
                    "finding_type": "Missing Header"
                })
                log(f"\n{darkcolours.BOLD}{darkcolours.FAIL}[!] Missing security header: {header}{darkcolours.ENDC}\n{darkcolours.OKBLUE}  Description:{darkcolours.ENDC} {details['description']}\n{darkcolours.OKGREEN}  Recommended Value:{darkcolours.ENDC} {details['mitigation']}\n{darkcolours.OKBLUE}  Scope:{darkcolours.ENDC} {rUrl}\n{darkcolours.OKBLUE}  Finding Type:{darkcolours.ENDC} Missing Header\n")
                log(f"{darkcolours.WARNING}**************************************************{darkcolours.ENDC}")
        report(rUrl, safe, unsafe)
        json_out.update(json_headers)
    if json_output:
        sys.stdout = sys.__stdout__
        print(json.dumps(json_out))

def parse_options():
    parser = OptionParser("Usage: %prog [options] <target>", prog=sys.argv[0])
    parser.add_option("-p", "--port", dest="port", help="Set a custom port to connect to", metavar="PORT")
    parser.add_option("-c", "--cookie", dest="cookie", help="Set cookies for the request", metavar="COOKIE_STRING")
    parser.add_option("-a", "--add-header", dest="custom_headers", help="Add headers for the request e.g. 'Header: value'", metavar="HEADER_STRING", action="append")
    parser.add_option('-d', "--disable-ssl-check", dest="ssldisabled", default=False, help="Disable SSL/TLS certificate validation", action="store_true")
    parser.add_option('-g', "--use-get-method", dest="useget", default=False, help="Use GET method instead HEAD method", action="store_true")
    parser.add_option('-m', "--use-method", dest="usemethod", default='HEAD', choices=["HEAD", "GET", "POST", "PUT", "DELETE", "TRACE"], help="Use a specified method",)
    parser.add_option("-j", "--json-output", dest="json_output", default=False, help="Print the output in JSON format", action="store_true")
    parser.add_option("--proxy", dest="proxy", help="Set a proxy (Ex: http://127.0.0.1:8080)", metavar="PROXY_URL")
    parser.add_option("--hfile", dest="hfile", help="Load a list of hosts from a flat file", metavar="PATH_TO_FILE")
    parser.add_option("--colours", dest="colours", help="Set up a colour profile [dark/light/none]", default="dark")
    parser.add_option("--colors", dest="colours", help="Alias for colours for US English")
    (options, targets) = parser.parse_args()
    return options, targets

if __name__ == "__main__":
    main()
