#!./.venv/bin/python3

# By: Matthew Bourn
# On: 2020-10-20, AI refactor 2026-08-14
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

##### Imports #####
import argparse
import sys

import socVars as v
import socFuncsIPs as ips
import socFuncsDoms as doms
import socFuncsHashs as hashes
from common import normalize_domain, print_finished, bang

################
##### MAIN #####
################
def main(argv=None):
    desc = (
        "Search free/commercial OSINT sources for reputation data on an IP, "
        "domain, or file hash (MD5 / SHA-1 / SHA-256)."
    )
    parser = argparse.ArgumentParser(description=desc)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="IPv4/IPv6 address to look up")
    group.add_argument("-H", "--hash", help="File hash (MD5, SHA-1, or SHA-256)")
    group.add_argument("-f", "--file",
        help="Local file: SHA-1 the file, then look up that hash",
    )
    group.add_argument("-d", "--domain", help="Domain name (or URL) to look up")
    args = parser.parse_args(argv)

    # If a local file is passed, get the hash and then act as though that hash was passed
    if args.file:
        args.hash = hashes.sha1File(args.file)

    # Get OSINT for a hash
    if args.hash:
        hsh = args.hash
        hashes.testHash(hsh)
        doms.genIL(hsh, v.ilToken, v.ilUrl)
        hashes.hashVT(hsh, v.vtToken, v.vtUrlHash)
        hashes.hashHA(hsh, v.haApiKey, v.haUrlV2)
        hashes.hashMB(hsh, v.mbToken, v.mbUrl, v.mbPostQ)
        hashes.hashMS(hsh, v.msToken, v.msUrl)

    # Get OSINT for an IP
    elif args.ip:
        ips.testIP(args.ip)
        ips.ipGEO(args.ip, v.ipaUrl)
        ips.ipHP(args.ip, v.hpToken, v.hpUrl)
        doms.genIL(args.ip, v.ilToken, v.ilUrl)
        ips.ipIQ(args.ip, v.iqUrl)
        ips.ipTR(args.ip, v.trUrl)
        ips.ipTF(args.ip, v.tfApiKey)
        ips.ipCL(args.ip, v.clUN, v.clPW, v.clUrl)
        ips.ipPassDnsOtx(args.ip, v.pdOtxUrl)
        ips.ipHA(args.ip, v.haApiKey, v.haUrlV2)
        ips.ipVT(args.ip, v.vtToken, v.vtUrlIP)

    # Get OSINT for a domain
    elif args.domain:
        domain = normalize_domain(args.domain)
        if not domain:
            print(bang + " Empty or invalid domain after normalization.")
            sys.exit(1)
        if domain != args.domain.strip():
            print(bang + " Normalized domain to: " + domain)

        # Start CheckPhish first (async job); print results after the other providers
        cp_target = doms.checkphish_scan_url(args.domain, domain)
        cp_job = doms.domCP_submit(cp_target, v.cpToken, v.cpUrl)

        doms.domPT(domain, v.ptToken, v.ptUA, v.ptUrl)
        # IOC Lists indexes the exact indicator; a full URL is not the same as the host
        il_term = args.domain.strip() or domain
        doms.genIL(il_term, v.ilToken, v.ilUrl)
        doms.domCL(domain, v.clUN, v.clPW, v.clUrl)
        ips.ipTF(domain, v.tfApiKey)
        doms.domHA(domain, v.haApiKey, v.haUrlV2)
        doms.domVT(domain, v.vtToken, v.vtUrlDom)
        doms.domUS(domain, v.usToken, v.usUrl)

        if cp_job:
            doms.domCP_result(cp_job, v.cpToken, v.cpUrl, cp_target)

    print_finished()

if __name__ == "__main__":
    main()
