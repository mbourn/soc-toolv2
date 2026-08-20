# By: Matthew Bourn
# On: 2020-10-20 (refactored 2026)
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

# DOMAINS #
###################################################################################################
##### Imports #####
###################################################################################################

import datetime as dt
import re
import time

import pypdns

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
)

###################################################################################################
##### Functions #####
###################################################################################################


## Universal Reputation Checker — IOC Lists
## GET /v1/indicator/entries?indicator=  (X-API-KEY)
## https://api.ioclists.com/swagger.json
def _il_endpoint(url):
    """Accept either the path or the old '?indicator=' suffix."""
    url = (url or "").strip()
    if "?indicator=" in url:
        url = url.split("?indicator=", 1)[0]
    return url.rstrip("/")


def genIL(ioc, token, url):
    print_section("Checking IOC Lists for Atomic")
    if not token:
        errSoft("IOC Lists is not configured (empty API key)", "")
        return None
    if not ioc:
        errSoft("empty indicator", "")
        return None

    endpoint = _il_endpoint(url)
    hdrs = {"X-API-KEY": token, "accept": "application/json"}
    # Use params= so : / ? & are encoded (do not concatenate a URL onto the query string)
    resJS = get_json(
        endpoint,
        headers=hdrs,
        params={"indicator": ioc},
        action="querying the IOC Lists API",
    )
    if resJS is None:
        return None

    if "error" in resJS and "search_results" not in resJS:
        errSoft("IOC Lists returned an error", resJS.get("error") or resJS)
        return None

    status = str(resJS.get("result") or "")
    hits = resJS.get("search_results")
    if hits is None:
        errSoft("the response: unrecognized format", resJS)
        return None

    print(plus + " Search term: " + BLUE + str(resJS.get("search_term") or ioc) + rst)
    if resJS.get("match_type"):
        print(plus + " Match type: " + str(resJS.get("match_type")))

    if status.upper() == "NOT_FOUND" or len(hits) == 0:
        print(plus + GREEN + " NO" + rst + " IOC Lists sources have flagged this atomic")
        return None

    feeds = []
    tags = []
    for item in hits:
        raw = item.get("raw") or ""
        # Hashtags that are not just YYYYMMDD date stamps
        for t in re.findall(r"#(\w+)", raw):
            if not re.fullmatch(r"20\d{6}", t):
                tags.append(t)
        if item.get("feedname"):
            feeds.append(item["feedname"])

    tags = sorted(set(tags))
    feeds = sorted(set(feeds))

    print(
        plus
        + " Result: "
        + RED
        + (status or "FOUND")
        + rst
        + " ("
        + str(len(hits))
        + " entries)"
    )
    if feeds:
        print(plus + " Feeds (" + str(len(feeds)) + "):")
        for feed in feeds[:8]:
            print(plus + plus + "\t" + RED + feed + rst)
        if len(feeds) > 8:
            print(plus + plus + RED + " ... Truncating ..." + rst)
    if tags:
        print(plus + " Tags:")
        for tag in tags[:8]:
            print(plus + plus + RED + "\t#" + tag + rst)
        if len(tags) > 8:
            print(plus + plus + RED + " ... Truncating ..." + rst)

    print(plus + " Sample entries:")
    shown = 0
    seen_raw = set()
    for item in hits:
        raw = (item.get("raw") or "").strip()
        if not raw or raw in seen_raw:
            continue
        seen_raw.add(raw)
        print(plus + plus + "\t" + raw)
        shown += 1
        if shown >= 5:
            break
    if len(hits) > shown:
        print(plus + plus + RED + " ... Truncating ..." + rst)
    return resJS


###################################################################################################
## Circl.lu Passive DNS
def domCL(dom, un, pw, url):
    print_section("Checking Circl.lu for Domain IP")
    try:
        cl = pypdns.PyPDNS(basic_auth=(un, pw))
        res = cl.rfc_query(dom, filter_rrtype="A")
        count = len(res)
        shown = res[:5] if count > 5 else res
        print(plus + f" Found {str(count)} entries")
        for r in shown:
            rrname = str(r.record.get("rrname", "") or "")
            rdata = str(r.record.get("rdata", "") or "")
            # CIRCL field orientation can vary; label IP vs name sensibly
            def _looks_ip(s):
                try:
                    import ipaddress
                    ipaddress.ip_address(s)
                    return True
                except ValueError:
                    return False

            if _looks_ip(rdata) and not _looks_ip(rrname):
                name, addr = rrname, rdata
            elif _looks_ip(rrname) and not _looks_ip(rdata):
                name, addr = rdata, rrname
            else:
                name, addr = rrname or "Not Found", rdata

            dFirstE = r.record.get("time_first", 0)
            dFirst = dt.datetime.fromtimestamp(int(dFirstE)).strftime("%F %X")
            dLastE = r.record.get("time_last", 0)
            dLast = dt.datetime.fromtimestamp(int(dLastE)).strftime("%F %X")
            print(plus + " Domain: " + GREEN + str(name) + rst)
            if addr:
                print(plus + plus + f" Address: {addr}")
            print(plus + plus + f" First: {dFirst}")
            print(plus + plus + f" Last: {dLast}")
        if count > 5:
            print(plus + plus + RED + " ... Truncating ..." + rst)
    except Exception as e:
        errSoft("querying the API for historical domain info", e)
        return None


###################################################################################################
## VirusTotal Domain Reputation
def domVT(dom, token, url):
    print_section("Checking Virus Total for Domain")
    hdrs = {"x-apikey": token}

    resJS = get_json(url + dom, headers=hdrs, action="querying the API for basic domain info")
    if resJS is None:
        return None

    if "error" in resJS:
        print(bang + " An error was returned from the API")
        print(bang + " " + str(resJS["error"].get("message", resJS["error"])))
        return None

    attrs = resJS.get("data", {}).get("attributes", {})

    if attrs.get("whois"):
        print(plus + " Select WHOIS Info")
        for line in attrs["whois"].split("\n"):
            key = line.split(":")[0] if ":" in line else ""
            if key in [
                "CIDR",
                "RegDate",
                "OrgName",
                "City",
                "Country",
                "Domain Status",
                "Creation Date",
            ]:
                print(plus + plus + "\t" + line)
    else:
        print(plus + GREEN + " No WHOIS Data" + rst + " Available from VirusTotal")

    if attrs.get("creation_date"):
        print(
            plus
            + " Registered: "
            + RED
            + str(dt.datetime.fromtimestamp(attrs["creation_date"]))
            + rst
        )

    categories = attrs.get("categories") or {}
    if categories:
        print(plus + " Categories: ")
        for src, cat in categories.items():
            print(plus + plus + "\t" + src + " - " + RED + str(cat) + rst)

    stats = attrs.get("last_analysis_stats") or {}
    print(plus + " Statistics:")
    for cat in ("harmless", "malicious", "suspicious"):
        val = stats.get(cat, 0)
        if cat == "harmless":
            color = GREEN if val > 0 else RED
        else:
            color = RED if val > 0 else GREEN
        print(plus + plus + "\t" + cat + ": " + color + str(val) + rst)

    mal_votes = attrs.get("total_votes", {}).get("malicious", 0)
    color = RED if mal_votes > 0 else GREEN
    print(plus + ' Community votes of "Malicious": ' + color + str(mal_votes) + rst)

    if stats.get("malicious", 0) > 0:
        results = attrs.get("last_analysis_results") or {}
        dets = [
            eng
            for eng, r in results.items()
            if r.get("category") == "malicious"
        ]
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

    # Communicating files
    resJS = get_json(
        url + dom + "/communicating_files",
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
        print(
            plus
            + GREEN
            + " No malicious files"
            + rst
            + " communicate with this domain"
        )
    else:
        print(
            plus
            + " Malicious files communicating with this domain: "
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

    print(plus + BLUE + " https://www.virustotal.com/gui/domain/" + dom + "/detection" + rst)


###################################################################################################
## Hybrid-Analysis Domain Lookup
def domHA(dom, apiKey, url):
    print_section("Checking Hybrid-Analysis for Domain")

    headers = {
        "api-key": apiKey,
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resJS = post_json(
        url,
        headers=headers,
        data=f"domain={dom}",
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
            + " are known to Hybrid-Analysis to communicate with this domain"
        )
        return None

    results = resJS.get("result") or []
    print(
        f"Found {RED} {str(count)} {rst} malicious files communicating with this domain:"
    )
    for item in results[:5]:
        print(
            plus
            + " File Name: "
            + RED
            + short_text(item.get("submit_name", "?"))
            + rst
        )
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


###################################################################################################
## PhishTank Domain Reputation
def domPT(dom, token, ua, url):
    print_section("Checking PhishTank for Domain")

    # PhishTank expects a full URL
    target = dom if dom.startswith("http") else "http://" + dom
    if target != dom:
        print(bang + " Adding " + RED + "'http://'" + rst + " to the domain string")

    headers = {"User-Agent": ua}
    pData = {"url": target, "format": "json", "app_key": token}

    res = post_response(
        url + target, headers=headers, data=pData, action="querying the API"
    )
    if res is None:
        return None

    try:
        resJS = res.json()
    except ValueError as e:
        errSoft("parsing the results into JSON", e)
        return None

    if "results" not in resJS:
        errSoft("sending request", resJS)
        return None

    results = resJS["results"]
    if results.get("in_database") is False:
        print(bang + " The domain has " + RED + "NOT been analyzed" + rst + " by PhishTank")
    elif results.get("valid") is True:
        print(plus + " Confirmed: " + RED + "Phishing Domain" + rst)
        print(plus + plus + "Analyzed on: " + str(results.get("verified_at", "")))
        print(plus + plus + BLUE + "\t" + str(results.get("phish_detail_page", "")) + rst)
    elif results.get("valid") is False and results.get("in_database"):
        print(
            plus
            + " Domain has been seen by PhishTank, but is "
            + YELLOW
            + "UNCONFIRMED"
            + rst
        )
        print(plus + plus + BLUE + str(results.get("phish_detail_page", "")) + rst)
    else:
        errSoft("parsing the results", resJS)
        return None


###################################################################################################
## CheckPhish / Bolster Scan API (submit-then-poll)
## Docs: https://bolster.ai/kbarticles/scan-apis-for-checkphish-users
CP_BAD = frozenset(
    {
        "phish",
        "likely_phish",
        "scam",
        "suspicious",
        "hacked_website",
        "cryptojacking",
    }
)
CP_CLEAN = frozenset({"clean"})


def checkphish_scan_url(raw, domain):
    """Use a full URL if the user passed one; otherwise https://<domain>."""
    raw = (raw or "").strip()
    if re.match(r"^https?://", raw, re.I):
        return raw
    return "https://" + domain


def _cp_endpoints(base):
    """base is .../neo/scan or the API root (.../api)."""
    base = (base or "").rstrip("/")
    if base.endswith("/neo/scan"):
        return base, base + "/status"
    if base.endswith("/api"):
        return base + "/neo/scan", base + "/neo/scan/status"
    # Default documented host
    return (
        "https://developers.checkphish.ai/api/neo/scan",
        "https://developers.checkphish.ai/api/neo/scan/status",
    )


def domCP_submit(scan_url, token, url_base):
    """Kick off a CheckPhish scan. Returns jobID or None. Does not wait."""
    print_section("Submitting CheckPhish scan (results after other checks)")
    if not token:
        errSoft("CheckPhish is not configured (empty API key)", "")
        return None

    scan_ep, _ = _cp_endpoints(url_base)
    body = {
        "apiKey": token,
        "urlInfo": {"url": scan_url},
        "scanType": "quick",
    }
    resJS = post_json(
        scan_ep,
        json_body=body,
        action="submitting the CheckPhish scan",
    )
    if resJS is None:
        return None
    if resJS.get("error"):
        errSoft("CheckPhish rejected the scan request", resJS.get("error"))
        return None

    job_id = resJS.get("jobID") or resJS.get("job_id")
    if not job_id:
        errSoft("CheckPhish did not return a jobID", resJS)
        return None

    print(plus + " Target: " + BLUE + scan_url + rst)
    print(plus + " Job ID: " + GREEN + str(job_id) + rst)
    print(plus + " Scan running in the background; results will print last.")
    return job_id


def domCP_result(job_id, token, url_base, scan_url, max_wait=60, interval=3):
    """Poll CheckPhish until DONE (or timeout) and print the verdict."""
    print_section("CheckPhish scan results")
    _, status_ep = _cp_endpoints(url_base)
    deadline = time.time() + max_wait
    last = None

    while time.time() < deadline:
        body = {"apiKey": token, "jobID": job_id, "insights": True}
        last = post_json(
            status_ep,
            json_body=body,
            action="polling CheckPhish scan status",
        )
        if last is None:
            return None
        if last.get("error"):
            err = last.get("error")
            status_code = None
            if isinstance(err, dict):
                status_code = err.get("status_code")
            if status_code == 429:
                time.sleep(interval + 2)
                continue
            errSoft("CheckPhish status query failed", err)
            return None

        status = str(last.get("status") or "").upper()
        if status == "DONE":
            break
        time.sleep(interval)
    else:
        print(
            bang
            + " CheckPhish scan did not finish within "
            + str(max_wait)
            + "s (job "
            + str(job_id)
            + ")"
        )
        if last:
            print(bang + " Last status: " + str(last.get("status", last)))
        return None

    disp = str(last.get("disposition") or "unknown")
    if disp in CP_CLEAN:
        disp_col = GREEN
    elif disp in CP_BAD:
        disp_col = RED
    else:
        disp_col = YELLOW

    print(plus + " URL: " + BLUE + str(last.get("url") or scan_url) + rst)
    print(plus + " Disposition: " + disp_col + disp + rst)
    if last.get("brand"):
        print(plus + " Targeted brand: " + RED + str(last["brand"]) + rst)
    if "resolved" in last:
        resolved = last["resolved"]
        rcol = GREEN if resolved else RED
        print(plus + " Resolved: " + rcol + str(resolved) + rst)

    cats = last.get("categories") or []
    if cats:
        print(plus + " Categories:")
        for cat in cats[:8]:
            if isinstance(cat, dict):
                name = cat.get("category", "?")
                score = cat.get("score", "")
                print(plus + plus + "\t" + str(name) + " (score " + str(score) + ")")
            else:
                print(plus + plus + "\t" + str(cat))

    if last.get("insights"):
        print(plus + " Insights: " + BLUE + str(last["insights"]) + rst)
    if last.get("screenshot_path"):
        print(plus + " Screenshot: " + BLUE + str(last["screenshot_path"]) + rst)
    return last


###################################################################################################
## urlscan.io historical Search API
## GET /api/v1/search?q=page.domain:...
## https://docs.urlscan.io/apis/urlscan-openapi/search/searchdatasource
US_DEFAULT_URL = "https://urlscan.io/api/v1/search"


def _us_hit_time(hit):
    """Sort key: newest first. Prefer sort[0] (epoch ms), else task.time."""
    sort = hit.get("sort")
    if isinstance(sort, list) and sort:
        try:
            return float(sort[0])
        except (TypeError, ValueError):
            pass
    return str((hit.get("task") or {}).get("time") or "")


def _us_web_result_url(hit):
    """Turn API result URL into the human web UI URL."""
    api = hit.get("result") or ""
    if "/api/v1/result/" in api:
        return api.replace("/api/v1/result/", "/result/")
    uuid = (hit.get("task") or {}).get("uuid") or hit.get("_id")
    if uuid:
        return "https://urlscan.io/result/%s/" % uuid
    return api


def _us_verdict_from_hit(hit, token):
    """Verdicts are often absent from search hits; pull from the result API if needed."""
    verdicts = hit.get("verdicts") or {}
    overall = verdicts.get("overall") if isinstance(verdicts, dict) else None
    if isinstance(overall, dict) and (
        overall.get("score") is not None or "malicious" in overall
    ):
        return overall.get("malicious"), overall.get("score")

    result_url = hit.get("result")
    if not result_url or not token:
        return None, None
    detail = get_json(
        result_url,
        headers={"api-key": token, "User-Agent": "soc-tool"},
        action="fetching urlscan result verdict",
    )
    if not detail:
        return None, None
    overall = (detail.get("verdicts") or {}).get("overall") or {}
    return overall.get("malicious"), overall.get("score")


def domUS(dom, token, url=None, size=5):
    print_section("Checking urlscan.io Search")
    if not token:
        errSoft("urlscan.io is not configured (empty API key)", "")
        return None

    endpoint = (url or US_DEFAULT_URL).rstrip("/")
    # Exact hostname match; quotes keep the query from being parsed as extra syntax
    query = 'page.domain:"%s"' % dom.replace('"', "")
    hdrs = {"api-key": token, "User-Agent": "soc-tool"}
    resJS = get_json(
        endpoint,
        headers=hdrs,
        params={"q": query, "size": str(size), "datasource": "scans"},
        action="querying the urlscan Search API",
    )
    if resJS is None:
        return None
    if resJS.get("status") == 400 or resJS.get("message"):
        # Some errors still return JSON
        if "results" not in resJS:
            errSoft("urlscan search failed", resJS.get("message") or resJS)
            return None

    hits = resJS.get("results") or []
    total = resJS.get("total", len(hits))
    if not hits:
        print(plus + GREEN + " NO" + rst + " historical urlscan results for this domain")
        return resJS

    hits = sorted(hits, key=_us_hit_time, reverse=True)
    shown = hits[:size]

    print(
        plus
        + " Historical scans: "
        + GREEN
        + str(total)
        + rst
        + " (showing "
        + str(len(shown))
        + " most recent)"
    )

    for hit in shown:
        page = hit.get("page") or {}
        stats = hit.get("stats") or {}
        title_txt = page.get("title")
        country = page.get("country")
        server = page.get("server")
        uniq = stats.get("uniqIPs")
        result_url = _us_web_result_url(hit)
        malicious, score = _us_verdict_from_hit(hit, token)

        print(plus + plus + " ---")
        if title_txt:
            print(plus + " Title: " + str(title_txt))
        if country:
            print(plus + " Country: " + GREEN + str(country) + rst)
        if server:
            print(plus + " Server: " + str(server))
        if uniq is not None:
            print(plus + " Unique IPs: " + str(uniq))
        if malicious is True:
            print(plus + " Verdict: " + RED + "malicious" + rst)
        elif malicious is False:
            print(plus + " Verdict: " + GREEN + "not malicious" + rst)
        if score is not None:
            scol = RED if (isinstance(score, (int, float)) and score > 0) else GREEN
            print(plus + " Score: " + scol + str(score) + rst)
        if result_url:
            print(plus + " Result: " + BLUE + str(result_url) + rst)
    return resJS
