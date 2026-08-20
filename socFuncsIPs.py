# By: Matthew Bourn
# On: 2020-10-20 (refactored 2026)
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

# IPS #
###################################################################################################
##### Imports #####
###################################################################################################

import datetime as dt
import ipaddress
import socket
import sys

import pypdns
import requests

import socLists
from common import (
    BLUE,
    GREEN,
    RED,
    YELLOW,
    bang,
    errSoft,
    get_json,
    get_text,
    plus,
    post_json,
    post_response,
    print_section,
    rst,
    short_text,
    title,
    DEFAULT_TIMEOUT,
)

###################################################################################################
##### Functions #####
###################################################################################################


def testIP(ip):
    print_section("Testing for valid IP")
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        print(bang + " " + str(e))
        print(bang + " Quitting!")
        sys.exit(1)
    print(plus + "               " + GREEN + "VALID" + rst)


###################################################################################################
## Circl.lu Passive DNS
def ipCL(ip, un, pw, url):
    print_section("Checking Circl.lu for Domain IP")
    try:
        # pypdns defaults to CIRCL; basic_auth is (username, password)
        cl = pypdns.PyPDNS(basic_auth=(un, pw))
        res = cl.rfc_query(ip, filter_rrtype="A")
        count = len(res)
        shown = res[:5] if count > 5 else res
        print(plus + f" Found {str(count)} entries")
        for r in shown:
            rrname = str(r.record.get("rrname", "") or "")
            rdata = str(r.record.get("rdata", "") or "")

            def _looks_ip(s):
                try:
                    ipaddress.ip_address(s)
                    return True
                except ValueError:
                    return False

            # Prefer the non-IP field as the domain name
            if _looks_ip(rdata) and not _looks_ip(rrname):
                dom = rrname or rdata
            elif _looks_ip(rrname) and not _looks_ip(rdata):
                dom = rdata or rrname
            else:
                dom = rdata or rrname or "Not Found"

            dFirstE = r.record.get("time_first", 0)
            dFirst = dt.datetime.fromtimestamp(int(dFirstE)).strftime("%F %X")
            dLastE = r.record.get("time_last", 0)
            dLast = dt.datetime.fromtimestamp(int(dLastE)).strftime("%F %X")
            print(plus + " Domain: " + GREEN + str(dom) + rst)
            print(plus + plus + f" First: {dFirst}")
            print(plus + plus + f" Last: {dLast}")
        if count > 5:
            print(plus + plus + RED + " ... Truncating ..." + rst)
    except Exception as e:
        errSoft("querying the API for historical IP info", e)
        return None

###################################################################################################
## IP-API.com Geolocation
def ipGEO(ip, url):
    print_section("Checking IP-API for Geolocation")
    resJS = get_json(url + ip, action="contacting IP-API's API")
    if resJS is None:
        return None

    if resJS.get("status") == "success":
        print(plus + "Country:\t" + GREEN + str(resJS.get("country", "")) + rst)
        print(plus + "Region:\t" + GREEN + str(resJS.get("regionName", "")) + rst)
        print(plus + "City:\t" + GREEN + str(resJS.get("city", "")) + rst)
    else:
        errSoft("with the API request", resJS)
        return None


###################################################################################################
## AV OTX Passive DNS
def ipPassDnsOtx(ip, url):
    print_section("AlienVault OTX Passive DNS")
    res = get_text(url + ip + "/passive_dns", action="retrieving data from OTX")
    if res is None:
        return None

    if res.status_code != 200:
        errSoft("retrieving data from OTX", res.reason)
        return None

    try:
        body = res.json()
    except ValueError as e:
        errSoft("parsing OTX response into JSON", e)
        return None

    count = body.get("count", 0)
    print(plus + " Resolutions Found: " + GREEN + str(count) + rst)

    if count == 0:
        print(bang + " No domain names found in the OTX Passive DNS DB")
        return None

    results = body.get("passive_dns") or []
    if count < 5:
        for obj in results:
            print(
                plus
                + plus
                + BLUE
                + obj.get("hostname", "?")
                + rst
                + " | Last seen: "
                + str(obj.get("last", ""))
            )
        return None

    # Compact multi-column view for larger result sets
    if len(results) > 24:
        results = results[:24]
    i = 1
    resStr = plus + plus + " "
    for obj in results:
        resStr += (
            BLUE
            + obj.get("hostname", "?")
            + rst
            + "("
            + str(obj.get("last", ""))
            + ")\t|\t"
        )
        if i % 4 == 0:
            print(resStr)
            resStr = plus + plus + " "
            i = 0
        i += 1
    if len(resStr) > 20:
        print(resStr)
    if count > 24:
        print(RED + "..... Truncating ....." + rst)


###################################################################################################
## VirusTotal: One stop shop
def ipVT(ip, token, url):
    print_section("Checking VirusTotal for IP")
    hdrs = {"x-apikey": token}

    resJS = get_json(url + ip, headers=hdrs, action="querying the API for basic IP info")
    if resJS is None:
        return None
    if "error" in resJS:
        errSoft("VirusTotal returned an error", resJS.get("error", {}).get("message", resJS))
        return None

    attrs = resJS.get("data", {}).get("attributes", {})

    # Print select WHOIS data
    if "whois" in attrs and attrs["whois"]:
        print(plus + " WHOIS Data")
        for line in attrs["whois"].split("\n"):
            key = line.split(":")[0] if ":" in line else ""
            if key in ["CIDR", "RegDate", "OrgName", "City", "Country"]:
                print(plus + plus + "\t" + line)
    else:
        print(plus + GREEN + " No WHOIS Data" + rst + " Available from VirusTotal")

    mal_votes = attrs.get("total_votes", {}).get("malicious", 0)
    color = RED if mal_votes > 0 else GREEN
    print(plus + ' Community votes of "Malicious": ' + color + str(mal_votes) + rst)

    # Sample detections
    dets = []
    for engine, result in (attrs.get("last_analysis_results") or {}).items():
        if result.get("category") in ("malicious", "suspicious"):
            dets.append((engine, result.get("category")))

    if len(dets) == 0:
        print(plus + " All engines marked the IP " + GREEN + "HARMLESS" + rst)
    else:
        print(plus + " Detections: " + RED + str(len(dets)) + rst)
        for engine, cat in dets[:5]:
            print(plus + plus + "\t" + engine + "- " + RED + cat + rst)
        if len(dets) > 5:
            print(plus + plus + RED + " ... Truncating ..." + rst)

    # DNS resolutions
    resJS = get_json(
        url + ip + "/resolutions",
        headers=hdrs,
        action="querying the API for DNS resolutions",
    )
    if resJS is None:
        return None

    data = resJS.get("data") or []
    if len(data) == 0:
        print(plus + GREEN + " No DNS Data" + rst + " available from VirusTotal")
    else:
        print(plus + " Number of Resolutions: " + GREEN + str(len(data)) + rst)
        for item in data[:5]:
            host = item.get("attributes", {}).get("host_name", "?")
            print(plus + plus + "\t" + BLUE + host + rst)
        if len(data) > 5:
            print(plus + plus + RED + " ... Truncating ..." + rst)

    # Communicating files
    resJS = get_json(
        url + ip + "/communicating_files",
        headers=hdrs,
        action="querying the API for communicating files",
    )
    if resJS is None:
        return None

    dets = [
        i
        for i in (resJS.get("data") or [])
        if i.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0
    ]

    if len(dets) == 0:
        print(plus + GREEN + " No malicious files" + rst + " communicate with this IP")
    else:
        print(
            plus
            + " Malicious files communicating with this IP: "
            + RED
            + str(len(dets))
            + rst
        )
        for item in dets[:5]:
            attrs_f = item.get("attributes", {})
            if "meaningful_name" in attrs_f:
                name = attrs_f["meaningful_name"]
            elif attrs_f.get("names"):
                name = attrs_f["names"][0]
            else:
                name = None
            if name:
                print(plus + plus + " Malicious file name: " + RED + name + rst)
            else:
                print(plus + plus + " VT has not saved a name for this file")
            mal = attrs_f.get("last_analysis_stats", {}).get("malicious", 0)
            print(plus + plus + " Flagged by " + RED + str(mal) + rst + " engines.")
        if len(dets) > 5:
            print(plus + plus + RED + " ... Truncating ..." + rst)

    print(plus + BLUE + " https://www.virustotal.com/gui/ip-address/" + ip + rst + "\n")


###################################################################################################
## Project HoneyPot: IP attack pattern analysis
## HTTPBL format: 127.<days_since_last_activity>.<threat_score>.<type>
def ipHP(ip, token, url):
    print_section("Checking Project HoneyPot for IP")

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        errSoft("validating IP for HoneyPot lookup", e)
        return None

    if addr.version != 4:
        print(bang + " Project HoneyPot HTTPBL supports IPv4 only; skipping")
        return None

    ipRev = ".".join(reversed(ip.split(".")))
    query_name = token + "." + ipRev + url

    try:
        answer = socket.gethostbyname(query_name)
    except socket.gaierror:
        # NXDOMAIN / not listed
        print(plus + " IP is " + RED + "NOT" + rst + " in the Project HoneyPot Database")
        return None
    except OSError as e:
        errSoft("querying Project HoneyPot DNSBL", e)
        return None

    parts = answer.split(".")
    if len(parts) != 4 or parts[0] != "127":
        print(bang + " Unrecognized response: " + answer)
        return None

    days_last, threat, type_code = parts[1], parts[2], parts[3]
    print(plus + " Last active (days ago): " + RED + days_last + rst)
    print(plus + " Threat lvl: " + RED + threat + rst)
    mean = [i for i in socLists.hpMeanings if i[0] == int(type_code)]
    if mean:
        print(plus + " Description: " + RED + mean[0][1] + rst)
    else:
        print(plus + " Description code: " + RED + type_code + rst)


###################################################################################################
## IP Intelligence: Identify VPN, Proxy, TOR exits
def ipII(ip, eAddy, url):
    print_section("Checking IP Intel if IP is TOR/VPN/Proxy Exit")
    print(bang + " This is an experimental service and returns inconsistent results")
    urlFull = url + ip + "&contact=" + eAddy

    res = get_text(urlFull, action="querying the API")
    if res is None:
        return None

    try:
        raw = res.content.decode("utf-8").strip()
        score = float(raw)
        num = int(score * 100)
    except (ValueError, UnicodeDecodeError) as e:
        errSoft("parsing the results", e)
        return None

    if score < 0:
        code = abs(int(score)) - 1
        msg = socLists.iiErrs[code] if 0 <= code < len(socLists.iiErrs) else "Unknown error"
        print(bang + " Error code: " + RED + raw + rst + " - " + msg)
    elif num > 100:
        print(bang + " Unknown error")
        print(bang + " " + raw)
    elif num > 89:
        print(plus + " The IP's score is (higher is worse): " + RED + str(num) + rst)
        print(
            plus
            + plus
            + " There is a "
            + RED
            + "HIGH"
            + rst
            + " probability that this is a TOR/VPN/Proxy exit"
        )
    else:
        print(plus + " The IP's score is: " + GREEN + str(num) + rst)
        print(
            plus
            + plus
            + " There is a "
            + GREEN
            + "LOW"
            + rst
            + " probability that this is a TOR/VPN/Proxy exit"
        )


###################################################################################################
## IP IQ Score: IP behavioral profile
def ipIQ(ip, url):
    print_section("Checking IP Quality Score for IP")
    ua = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36"
    )
    args = {
        "strictness": "0",
        "allow_public_access_points": "true",
        "user_agent": ua,
        "user_language": "en-US",
    }
    profiles = [
        "is_crawler",
        "mobile",
        "host",
        "proxy",
        "vpn",
        "tor",
        "active_vpn",
        "active_tor",
        "device_brand",
        "device_model",
        "recent_abuse",
        "bot_status",
    ]

    resJS = get_json(url + ip, params=args, action="querying the API")
    if resJS is None:
        return None

    try:
        if resJS.get("success") is True:
            print(plus + " IP Profile Report:")
            for key in profiles:
                if key not in resJS:
                    continue
                val = resJS[key]
                if val is True:
                    print(plus + plus + " " + key.capitalize() + ": " + RED + "TRUE" + rst)
                elif val is False:
                    print(plus + plus + " " + key.capitalize() + ": " + GREEN + "False" + rst)
                elif val not in (None, ""):
                    print(plus + plus + " " + key.capitalize() + ": " + GREEN + str(val) + rst)
        else:
            print(bang + " No profile report available for this IP")
            print(resJS)
    except (TypeError, KeyError) as e:
        errSoft("working with the response JSON object", e)
        return None


###################################################################################################
## TOR Relay/Exit List
def ipTR(ip, url):
    print_section("Checking IP With TOR Project")

    resJS = get_json(url + ip, action="querying the TOR Project API")
    if resJS is None:
        return None

    print(
        plus
        + " TOR relay/exit list last updated: "
        + GREEN
        + str(resJS.get("relays_published", "?"))
        + rst
    )
    relays = resJS.get("relays") or []
    if len(relays) > 0:
        print(plus + plus + RED + "\tCONFIRMED" + rst + " TOR node")
        print(plus + plus + "\tNode Name: " + str(relays[0].get("n", "?")))
        print(plus + plus + "\tFingerprint: " + str(relays[0].get("f", "?")))
    else:
        print(bang + " IP is " + GREEN + "NOT" + rst + " listed by TOR as a node")


###################################################################################################
## ThreatFox IOC - IP or domain search term
def ipTF(ioc, apiKey):
    print_section("Checking IOC with ThreatFox")

    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": apiKey}
    body = {"query": "search_ioc", "search_term": ioc}

    res = post_response(
        url, headers=headers, json_body=body, action="ThreatFox API call"
    )
    if res is None:
        return None

    if res.status_code != 200:
        errSoft(
            "ThreatFox API request failed - {}".format(res.status_code),
            res.text,
        )
        return None

    try:
        resJson = res.json()
    except ValueError as e:
        errSoft("Failed to convert returned data to json", e)
        return None

    status = resJson.get("query_status", "Not Found")
    if status != "ok":
        print(bang + f" Search result: {status}")
        return None

    data_list = resJson.get("data") or []
    if not data_list:
        print(bang + " No IOC data returned")
        return None

    # Show first hit; note if more exist
    data = data_list[0]
    if len(data_list) > 1:
        print(plus + f" {len(data_list)} hits; showing first")

    print(plus + " Malware: " + RED + str(data.get("malware", "?")) + rst)
    if data.get("malware_alias"):
        print(plus + " Alias: " + RED + str(data["malware_alias"]) + rst)
    print(plus + " Threat Type: " + RED + str(data.get("threat_type", "?")) + rst)
    print(plus + " Confidence: " + RED + str(data.get("confidence_level", "?")) + rst)

    samples = data.get("malware_samples") or []
    if samples:
        print(plus + " Samples: ")
        for sample in samples[:5]:
            print(
                plus
                + plus
                + " Data collected on: {}".format(
                    BLUE + str(sample.get("time_stamp", "")) + rst
                )
            )
            for key, val in sample.items():
                if "hash" not in key and "time" not in key:
                    print(plus + plus + " {}: {}".format(key, BLUE + str(val) + rst))

    tags = data.get("tags") or []
    if tags:
        print(plus + " Tags: ")
        for tag in tags:
            print("\t{}".format(RED + str(tag) + rst))

    if data.get("malware_malpedia"):
        print(plus + " Malpedia: {}".format(BLUE + str(data["malware_malpedia"]) + rst))


###################################################################################################
## Hybrid-Analysis IP Lookup
def ipHA(ip, apiKey, url):
    print_section("Checking Hybrid-Analysis for IP")

    headers = {
        "api-key": apiKey,
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resJS = post_json(
        url,
        headers=headers,
        data=f"host={ip}",
        action="creating the session object and sending the query",
    )
    if resJS is None:
        return None

    count = resJS.get("count", 0)
    if count == 0:
        print(
            plus
            + GREEN
            + " No malicious files"
            + rst
            + " are known to Hybrid-Analysis to communicate with this IP."
        )
        return None

    results = resJS.get("result") or []
    shown = results[:5]
    print(
        f"Found {RED} {str(count)} {rst} malicious files communicating with this IP:"
    )
    for item in shown:
        print(
            plus
            + " File Name: "
            + RED
            + short_text(item.get("submit_name", "?"))
            + rst
        )
        print(plus + plus + f"\tAnalyzed on: {item.get('analysis_start_time', '?')}")
        print(
            plus
            + plus
            + "\tMalware Family: "
            + RED
            + str(item.get("vx_family"))
            + rst
        )
        print(
            plus
            + plus
            + "\tThreat Score: "
            + RED
            + str(item.get("threat_score"))
            + rst
        )
        sha = item.get("sha256", "")
        print(
            plus
            + plus
            + "\tURL: "
            + BLUE
            + "https://www.hybrid-analysis.com/sample/"
            + sha
            + rst
        )
    if count > 5:
        print(f"{RED} ... Truncating ... {rst}")