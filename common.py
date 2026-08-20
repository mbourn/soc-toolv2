# By: Matthew Bourn
# On: 2020-10-20, AI refactor 2026-08-14
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

##### Shared helpers for the SOC OSINT tool #####
from __future__ import annotations

import re
import sys
import requests

from typing import Any, Optional
from urllib.parse import urlparse

import socVars as v
from socVars import bang, plus, rst, title  # noqa: F401 - re-export
from socVars import BLUE, GREEN, RED, WHITE, YELLOW  # noqa: F401 - re-export

# Default HTTP timeout (seconds) for all provider calls
DEFAULT_TIMEOUT = 15

### Print a non-fatal error and continue. ###
def errSoft(m: str, e: Any = "") -> None:
    print(bang + " Something went wrong when " + m)
    if e not in ("", None):
        print(bang + " " + str(e))
    print(bang + " Skipping!")

### Print a fatal error and exit. ###
def errHard(m: str, e: Any = "") -> None:
    print(bang + " " + m)
    if e not in ("", None):
        print(bang + " " + str(e))
    print(bang + " Quitting!")
    sys.exit(1)

### Print section header ###
def print_section(label: str) -> None:
    print("\n[-] " + title + "----- " + label + " -----" + rst + " [-]")

### Print final finish footer ###
def print_finished() -> None:
    print("\n[-] " + title + "----- FINISHED -----" + rst + " [-]")
    print("\n")

### If provided list is longer than 5, truncate to 5, and return ###
def truncate_items(items: list, limit: int = 5) -> tuple[list, int]:
    count = len(items)
    if count > limit:
        return items[:limit], count
    return items, count

### Print truncation note if list has been truncated ###
def print_truncated_note(count: int, limit: int = 5) -> None:
    if count > limit:
        print(plus + plus + RED + " ... Truncating ..." + rst)

### Truncate long strings, eg HA submition names are full URLs ###
def short_text(text: Any, max_len: int = 80) -> str:
    s = str(text)
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."

### Normalize the submitted domain name ###
def normalize_domain(dom: str) -> str:
    """Strip scheme, credentials, path, query, and trailing dots/slashes from a domain/URL."""
    if not dom:
        return dom
    dom = dom.strip()

    # If it looks like a URL, parse host; otherwise treat as bare domain/host
    if "://" in dom:
        parsed = urlparse(dom)
        host = parsed.hostname or parsed.netloc
        if host:
            return host.rstrip(".").lower()
        dom = re.sub(r"^https?://", "", dom, flags=re.I)
    
    # Drop path/query if present without scheme
    dom = dom.split("/")[0].split("?")[0].split("#")[0]
    
    # Drop userinfo@ if any
    if "@" in dom:
        dom = dom.rsplit("@", 1)[-1]
    
    # Drop port
    if dom.count(":") == 1 and not dom.startswith("["):
        host, _, port = dom.partition(":")
        if port.isdigit():
            dom = host
    return dom.rstrip(".").lower()

### GET and parse JSON. On failure, soft-error and return None ###
def get_json(
    url: str,
    *,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    action: str = "querying the API",
    raise_for_status: bool = False,
) -> Optional[Any]:
    try:
        res = requests.get(url, headers=headers, params=params, timeout=timeout)
        if raise_for_status:
            res.raise_for_status()
    except requests.RequestException as e:
        errSoft(action, e)
        return None
    try:
        return res.json()
    except ValueError as e:
        errSoft("parsing the response into JSON", e)
        return None

### POST and parse JSON. On failure, soft-error and return None ###
def post_json(
    url: str,
    *,
    headers: Optional[dict] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: int = DEFAULT_TIMEOUT,
    action: str = "querying the API",
    raise_for_status: bool = False,
) -> Optional[Any]:
    try:
        res = requests.post(
            url, headers=headers, data=data, json=json_body, timeout=timeout
        )
        if raise_for_status:
            res.raise_for_status()
    except requests.RequestException as e:
        errSoft(action, e)
        return None
    try:
        return res.json()
    except ValueError as e:
        errSoft("parsing the response into JSON", e)
        return None

### Do GET, return the Response or None on transport error """
def get_text(
    url: str,
    *,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    action: str = "querying the API",
) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers=headers, params=params, timeout=timeout)
    except requests.RequestException as e:
        errSoft(action, e)
        return None


### Do POST, return the Response or None on transport error """
def post_response(
    url: str,
    *,
    headers: Optional[dict] = None,
    data: Any = None,
    json_body: Any = None,
    timeout: int = DEFAULT_TIMEOUT,
    action: str = "querying the API",
) -> Optional[requests.Response]:
    try:
        return requests.post(
            url, headers=headers, data=data, json=json_body, timeout=timeout
        )
    except requests.RequestException as e:
        errSoft(action, e)
        return None

