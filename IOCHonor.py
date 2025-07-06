import argparse
import sys
from wsgiref import headers
import requests
import re
import os.path
import mimetypes
import json
from dotenv import load_dotenv

def argumentparser():
    parser = argparse.ArgumentParser(description='IOC Enrichment')
    parser.add_argument('--i', help='Inform the desired IOC (IP, domain, file, hash, etc.')
    args = parser.parse_args()
    return args

def argumentisvalid(regexlist,ioc_value):
    for ioc, regex in regexlist.items():
        result = re.search(regex, ioc_value)
        if result:
            return ioc, result.group()
        # In case it's a file
        elif os.path.isfile(argumentparser().i):
            return "file", argumentparser().i
    return None

def virustotal_get_method(endpoint, virustotal_api_key):
    url = f"https://www.virustotal.com/api/v3/analyses/{endpoint}"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }
    response = requests.get(url, headers=headers)
    return response.json()

def otx_get_method(endpoint,ioc_type, otx_api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{endpoint}/general"
    response = requests.request(method='GET', url=url)
    return response.json()

def abuseipdscore(ip,abuseipd_api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuseipd_api_key
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    return response.json()
    ## learn abt it later
    # Formatted output
    # decodedResponse = json.loads(response.text)
    # print json.dumps(decodedResponse, sort_keys=True, indent=4)

def otxipinfo(ip,otx_api_key):
    response1 = otx_get_method(ip,'IPv4',otx_api_key)
    if response1.status_code != 200:
        return otx_get_method(ip,'IPv6',otx_api_key)
    return response1.json()

def otxdomaininfo(domain,otx_api_key):
    otx_get_method(domain,'domain',otx_api_key)

def otxfilehashinfo(file_hash,otx_api_key):
    otx_get_method(file_hash,'file',otx_api_key)

def analysisbyvirustotalid(fileid, virustotal_api_key):
    virustotal_get_method(fileid, virustotal_api_key)

def analyzehash(virustotal_api_key, filehash):
    virustotal_get_method(filehash, virustotal_api_key)

def analyzedomain(virustotal_api_key, domain):
    virustotal_get_method(domain, virustotal_api_key)

def anaylzeip(virustotal_api_key, ip):
    virustotal_get_method(ip, virustotal_api_key)

def analyzeurl(virustotal_api_key, url):
    get_id = uploadurltovirustotal(url, virustotal_api_key)
    virustotal_get_method(get_id, virustotal_api_key)

def analyzefile(virustotal_api_key, file):
    get_id = uploadfiletovirustotal(file, virustotal_api_key)
    virustotal_get_method(get_id, virustotal_api_key)

def uploadfiletovirustotal(file, virustotal_api_key):
    # taking file identifier to use on API
    mime_type, encoding = mimetypes.guess_type(file)
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": (file, open(file, "rb"), mime_type)}
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }
    response = requests.post(url, files=files, headers=headers)
    return response.json()["data"]["id"]

def uploadfiletootx(file, otx_api_key):
    # taking file identifier to use on API
    mime_type, encoding = mimetypes.guess_type(file)
    url = f'https://otx.alienvault.com/api/v1/indicators/submit_file'
    files = {"file": (file, open(file, "rb"), mime_type)}
    headers = {
        "accept": "multipart/form-data",
         "X-OTX-API-KEY": otx_api_key
    }
    response = requests.post(url, files=files, headers=headers)
    return response.json()

def uploadurltovirustotal(input_url, virustotal_api_key):
    url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": input_url}
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, data=payload, headers=headers)
    return response.json()["data"]["url"]

def uploadurltootx(input_url, otx_api_key):
    url = 'https://otx.alienvault.com/api/v1/indicators/submit_url'
    payload = {"url": input_url}
    headers = {
        "accept": "application/json",
        "X-OTX-API-KEY": otx_api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, data=payload, headers=headers)
    return response.json()

def main():
    args = argumentparser()
    load_dotenv()
    virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
    abuseipd_key = os.getenv("ABUSEIPD_API_KEY")
    otx_api_key = os.getenv("OTX_API_KEY")
    regexes = {"md5": r"^[a-fA-F0-9]{32}$", "shad256": r"^[a-fA-F0-9]{64}$", "sha1": r"^[a-fA-F0-9]{40}$",
               "domain": r"^((?!-)[A-Za-z0-9-]{1, 63}(?<!-)\.)+[A-Za-z]{2, 6}$",
               "ipv4/ipv6":(r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}"
                            r"|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]"
                            r"|1[0-9]{2}|[1-9]?[0-9])|(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:)"
                           r"{1,7}:|:(:[0-9A-Fa-f]{1,4}){1,7}|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]"
                            r"{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|"
                            r"([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]"
                            r"{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}|:(:[0-9A-Fa-f]{1,4}){1,6}))$"),
               "url": (r"(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z]{2,}(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?\/[a-zA-Z0-9]{2,}|"
                       r"((https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z]{2,}(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?)|(https:\/\/www\."
                       r"|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z0-9]{2,}\.[a-zA-Z0-9]{2,}\.[a-zA-Z0-9]{2,}(\.[a-zA-Z0-9]{2,})?")}
    argument = argumentisvalid(regexes,args.i)


    #if not argument:
     #   print(f"ValueError: Invalid IOC format: {args.i}")
     #   sys.exit(1)

if __name__ == "__main__":
    main()