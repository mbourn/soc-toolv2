# By: Matthew Bourn
# On: 2020-10-20
# ©: GNU GPLv3
# Do: at your own risk; copy, modify, share, give me a nod.  Don't sell.

# VARIABLES #
###################################################################################################
##### Imports #####
###################################################################################################

## Standard Modules
from colorama import Fore as fr
from colorama import Back as bk
from colorama import Style as styl

###################################################################################################
##### Variables #####
###################################################################################################

##### Define Text Colors #####
RED = fr.RED+styl.BRIGHT
BLUE = fr.BLUE+styl.BRIGHT
WHITE = fr.WHITE+styl.BRIGHT
GREEN = fr.GREEN+styl.BRIGHT
YELLOW = fr.YELLOW+styl.BRIGHT

rst = styl.RESET_ALL
bang = RED+ '[!]' +rst
plus = GREEN+ '[+]' +rst
title = bk.WHITE+styl.DIM+fr.BLACK

###################################################################################################
## ThreatFox ##
tfApiKey = ""

###################################################################################################
## Circl.lu ##
clUrl = 'circl.lu'
clUN = ""
clPW = ""

###################################################################################################
## IP-API.com ##
ipaUrl = "http://ip-api.com/json/"

###################################################################################################
## IOCLists ##
ilToken = ""
ilUrl = "https://api.ioclists.com/v1/indicator/entries"

###################################################################################################
## Phish Tank ##
# The documentation is terrible
## Request URL must be "httpS" not "http"
## Request URL must be "https://checkurl.phishtank.com/checkurl/index.php?url=xxxx"
## Translate this to English https://blog.csdn.net/m0_37605407/article/details/105236971
ptToken = ""
ptUrl = "https://checkurl.phishtank.com/checkurl/index.php?url="
ptUA = "phishtank/matthewhb"

###################################################################################################
## CheckPhish / Bolster Scan API ##
# https://bolster.ai/kbarticles/scan-apis-for-checkphish-users
cpToken = ""
cpUrl = "https://developers.checkphish.ai/api"

###################################################################################################
## IP Quality Score ## 
# https://www.ipqualityscore.com/documentation/proxy-detection/best-practices
iqToken = ""
iqUrlBase = "https://ipqualityscore.com/api/json/ip/"
iqUrl = iqUrlBase + iqToken + "/"

###################################################################################################
## IP Intelligence ##
# https://getipintel.net/free-proxy-vpn-tor-detection-api/
iiEAddy = ""
iiUrl = "http://check.getipintel.net/check.php?ip="

###################################################################################################
## Malware Bazaar ##
mbToken = ""
mbUrl = "https://mb-api.abuse.ch/api/v1/"
mbPostQ = '"query": "get_info"'

###################################################################################################
## MalShare ##
msToken = ""
msUrl = "https://malshare.com/api.php?api_key=" + msToken + "&action=search&query="

###################################################################################################
## VirusTotal ##
vtToken = ""
vtUrlIP = "https://www.virustotal.com/api/v3/ip_addresses/"
vtUrlHash = "https://www.virustotal.com/api/v3/files/"
vtUrlDom = "https://www.virustotal.com/api/v3/domains/"

###################################################################################################
## Operation Honeypot ##
hpToken = ""
hpUrl = ".dnsbl.httpbl.org"

###################################################################################################
## AlienVault OTX Passive DNS
pdOtxUrl = "https://otx.alienvault.com/api/v1/indicators/IPv4/"

###################################################################################################
## View DNS ##
vdnsToken = ""
vdnsUrl = "https://api.viewdns.info/reversedns/?ip=IP&apikey=" + vdnsToken + "&output=json"

###################################################################################################
## Hybrid-Analysis ##
haApiKey = ""
haUrlV2  = 'https://hybrid-analysis.com/api/v2/search/terms'

###################################################################################################
## urlscan.io Search ##
# https://docs.urlscan.io/apis/urlscan-openapi/search/searchdatasource
usToken = ""
usUrl = "https://urlscan.io/api/v1/search"

###################################################################################################
## TOR Project ##
trUrl = "https://onionoo.torproject.org/summary?limit=1&search="



