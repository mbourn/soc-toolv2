# By: Matthew Bourn
# On: 2020-10-20 (refactored 2026)
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

# HASHES #
###################################################################################################
##### Imports #####
###################################################################################################

import hashlib
from pathlib import Path

import requests
from hashid import HashID

from common import (
    BLUE,
    GREEN,
    RED,
    WHITE,
    YELLOW,
    bang,
    errHard,
    errSoft,
    get_json,
    get_text,
    plus,
    post_json,
    post_response,
    print_section,
    rst,
    title,
    DEFAULT_TIMEOUT,
)

###################################################################################################
##### Functions #####
###################################################################################################


def testHash(hsh):
    print_section("Testing hash")
    try:
        hID = HashID()
        res = hID.identifyHash(hsh)
        hash_types = []
        for match in res:
            hash_types.append(match[0].split("(")[0])
        hash_types = list(set(hash_types))
    except Exception as e:
        print(bang + " Do you have hashid installed? 'pip install hashid'")
        print(bang + " " + str(e))
        return

    print(plus + " Hash looks like:")
    if len(hash_types) > 0:
        outStr = plus + plus + "\t|"
        i = 1
        for htype in hash_types:
            outStr += htype.replace("[+]", "") + "|"
            if i % 5 == 0:
                print(outStr)
                outStr = plus + plus + "\t|"
            i += 1
        print(outStr)

        accepted = {"SHA-1", "SHA-256", "MD5"}
        if not accepted.intersection(hash_types):
            # hashid labels vary; also accept common aliases
            joined = " ".join(hash_types).upper()
            if not any(x in joined for x in ("MD5", "SHA-1", "SHA1", "SHA-256", "SHA256")):
                errHard(
                    "OSINT providers only accept MD5, SHA-1, or SHA-256. "
                    "Please try again with one of those hash types."
                )
    else:
        errHard(
            "Unknown hash type. OSINT providers only accept MD5, SHA-1, or SHA-256."
        )


def sha1File(path):
    """Return the SHA-1 hex digest of a local file. Exits on missing/unreadable path."""
    print_section("Hashing local file (SHA-1)")
    p = Path(path).expanduser()
    if not p.is_file():
        errHard("Not a readable file: " + str(p))

    h = hashlib.sha1()
    try:
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as e:
        errHard("Failed to read " + str(p), e)

    digest = h.hexdigest()
    print(plus + " File: " + WHITE + str(p.resolve()) + rst)
    print(plus + " SHA-1: " + GREEN + digest + rst)
    return digest


###################################################################################################
## Malware Bazaar Malware Library
def hashMB(hsh, token, url, postQuery):
    print_section("Checking Malware Bazaar for hash")
    postData = {"query": "get_info", "hash": hsh}
    postHeaders = {"Auth-Key": token}

    res = post_json(
        url, headers=postHeaders, data=postData, action="querying the API"
    )
    if res is None:
        return None

    if res.get("query_status") == "hash_not_found":
        print(bang + " File is " + RED + "NOT" + rst + " in the Malware Bazaar library")
        return None

    if "data" not in res or not res["data"]:
        errSoft("parsing the response", res)
        return None

    entry = res["data"][0]
    print(plus + " File Name: " + str(entry.get("file_name", "?")))
    print(plus + " File Type: " + str(entry.get("file_type_mime", "?")))
    print(plus + " First Seen: " + str(entry.get("first_seen", "?")))

    clamav = (entry.get("intelligence") or {}).get("clamav")
    if clamav is None:
        print(plus + " File is available, but there are no Clamav detections")
    elif len(clamav) > 0:
        print(plus + " Detections:")
        for det in clamav[:5]:
            print(plus + plus + "\t" + RED + str(det) + rst)
        if len(clamav) > 5:
            print(plus + plus + RED + " ... Truncating ..." + rst)

    sha = entry.get("sha256_hash", hsh)
    print(plus + " Analysis: " + BLUE + "https://bazaar.abuse.ch/sample/" + sha + "/" + rst)


###################################################################################################
## MalShare Malware Library
def hashMS(hsh, token, url):
    print_section("Checking MalShare for hash")
    # MalShare frequently is slow; timeout is important
    res = get_text(url + hsh, timeout=DEFAULT_TIMEOUT, action="querying the API")
    if res is None:
        return None

    try:
        resJS = res.json()
    except ValueError as e:
        errSoft("converting the response to JSON", e)
        return None

    if not resJS or len(resJS) == 0:
        print(bang + " File is " + RED + "NOT" + rst + " in the MalShare library")
        return None

    import datetime as dt

    first = resJS[0] if isinstance(resJS, list) else resJS
    if isinstance(first, dict) and "sha1" in first:
        print(plus + " Arch type: " + RED + str(first.get("type", "?")) + rst)
        if "added" in first:
            print(
                plus
                + " Uploaded: "
                + RED
                + str(dt.datetime.fromtimestamp(first["added"]))
                + rst
            )
        src = str(first.get("source", "")).replace(".", "[DOT]")
        print(plus + " Src URL: " + RED + src + rst)
        print(
            plus
            + " Analysis: "
            + BLUE
            + "https://malshare.com/search.php?query="
            + hsh
            + rst
        )
    else:
        errSoft("parsing the response", resJS)
        return None


###################################################################################################
## Hybrid-Analysis Hash Reputation
def hashHA(hsh, token, url):
    print_section("Checking Hybrid-Analysis for hash")

    # URL is typically .../search/terms; hash endpoint is .../search/hash
    parts = url.rstrip("/").split("/")
    parts[-1] = "hash"
    urlBuilt = "/".join(parts)

    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    )
    postHeaders = {"User-agent": ua, "api-key": token}
    postData = {"hash": hsh}

    resJson = post_json(
        urlBuilt, headers=postHeaders, data=postData, action="querying the API"
    )
    if resJson is None:
        return None

    # API returns a list of reports; pick the richest entry
    if isinstance(resJson, list):
        if len(resJson) == 0:
            print(
                bang
                + " File has "
                + RED
                + "NOT"
                + rst
                + " been analyzed by Hybrid Analysis"
            )
            return None
        resData = max(resJson, key=lambda e: len(e) if isinstance(e, dict) else 0)
    elif isinstance(resJson, dict):
        resData = resJson
    else:
        errSoft("unexpected Hybrid-Analysis response shape", type(resJson))
        return None

    if resData.get("verdict") not in (None, ""):
        ver = resData["verdict"]
        if ver == "malicious":
            ver_disp = RED + ver + rst
        elif ver == "whitelisted":
            ver_disp = GREEN + ver + rst
        else:
            ver_disp = YELLOW + str(ver) + rst
        print(plus + " Verdict: " + ver_disp)

    if resData.get("vx_family"):
        print(plus + " VX Family: " + RED + str(resData["vx_family"]) + rst)

    if "av_detect" in resData and resData["av_detect"] is not None:
        dets = resData["av_detect"]
        try:
            dets_n = int(dets)
        except (TypeError, ValueError):
            dets_n = 0
        if dets_n == 0:
            dets_disp = GREEN + str(dets) + rst
        elif dets_n < 6:
            dets_disp = YELLOW + str(dets) + rst
        else:
            dets_disp = RED + str(dets) + rst
        print(plus + " AV Detections: " + dets_disp)

    if isinstance(resData.get("threat_level"), int):
        tLev = resData["threat_level"]
        if tLev == 0:
            t_disp = GREEN + str(tLev) + rst
        elif tLev < 15:
            t_disp = YELLOW + str(tLev) + rst
        else:
            t_disp = RED + str(tLev) + rst
        print(plus + " Threat Score: " + t_disp)

    if "submit_name" in resData:
        print(plus + " File Name: " + WHITE + str(resData["submit_name"]) + rst)

    hosts = resData.get("hosts") or []
    if hosts:
        print(plus + " Contacted IPs:")
        for ip in hosts[:10]:
            print(plus + plus + " " + WHITE + str(ip) + rst)

    domains = resData.get("domains") or []
    if domains:
        print(plus + " Contacted Domains:")
        for dom in domains[:10]:
            print(plus + plus + " " + WHITE + str(dom) + rst)

    if resData.get("sha256"):
        url = "https://www.hybrid-analysis.com/sample/" + resData["sha256"]
        if resData.get("environment_id") not in (None, ""):
            url += "?environmentId=" + str(resData["environment_id"])
        print(plus + " Analysis URL: " + BLUE + url + rst)


###################################################################################################
## VirusTotal Hash Reputation
def hashVT(hsh, token, url):
    print_section("Checking VirusTotal for hash")
    hdrs = {"x-apikey": token}

    res = get_text(url + hsh, headers=hdrs, timeout=DEFAULT_TIMEOUT, action="querying the API")
    if res is None:
        return None

    try:
        jsn = res.json()
    except ValueError as e:
        errSoft("converting the response to JSON", e)
        return None

    if "error" in jsn and jsn["error"].get("code") == "NotFoundError":
        print(
            bang + " File has " + RED + "NOT" + rst + " been analyzed by VirusTotal"
        )
        return None

    try:
        results = jsn["data"]["attributes"]["last_analysis_results"]
        dets = [i for i in results if results[i].get("category") == "malicious"]
        unDets = [i for i in results if results[i].get("category") == "undetected"]
        sha256 = jsn["data"]["attributes"].get("sha256", hsh)
    except (KeyError, TypeError) as e:
        errSoft("loading the analysis results", e)
        return None

    if len(dets) > 0:
        print(plus + " Number of detections: " + RED + str(len(dets)) + rst)
        print(plus + " Example Types:")
        for eng in dets[:5]:
            print(
                plus
                + plus
                + "\t"
                + eng
                + ": "
                + RED
                + str(results[eng].get("result", ""))
                + rst
            )
        if len(dets) > 5:
            print(plus + plus + RED + " ... Truncating ..." + rst)
        print(
            plus
            + " Analysis URL: "
            + BLUE
            + "https://www.virustotal.com/gui/file/"
            + sha256
            + "/detection"
            + rst
        )
    elif len(unDets) > 0:
        print(
            plus
            + " File was analyzed by "
            + GREEN
            + str(len(unDets))
            + rst
            + " engines and flagged by "
            + GREEN
            + "NONE"
            + rst
            + " of them"
        )
        print(
            plus
            + " Analysis URL: "
            + BLUE
            + "https://www.virustotal.com/gui/file/"
            + sha256
            + "/detection"
            + rst
        )
