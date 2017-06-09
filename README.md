# AlienVault_OTX-SIEM
AlienVault OTX API download Indicators of Compromise to a format suitable for SIEM Import

Credits:

Using AlienVault OTX API Scripts and documentation @ https://github.com/AlienVault-OTX/OTX-Python-SDK
Based on original code by Florian Roth / Neo23x0 @ https://github.com/Neo23x0/signature-base
References https://www.bsk-consulting.de/2015/09/06/splunk-threat-intel-ioc-integration-via-lookups/

Simplified and tweaked to support one function - download of subscribed pulses in a format suitable for SIEM Import - designed to support ArcSight, but other vendors will also work.

Supports the download of the following indicators:
* Hashes (MD5, SHA1, SHA256)
* IP Addresses (IPv4 , IPv6)
* Domains / Hostnames
* URL's / URI's
* Email Addresses
* Mutexes
* CVE's


For a list of good quality users to subscribe to, review the otx.pulses file

# USE

The scripts are contained within the /bin/ directory
run get-otx-iocs.py to gather the IOCS


Enter your AlienVault API Key in file /bin/get-otx-iocs.py:

OTX_KEY = ''

e.g. 
OTX_KEY = 'e59df4e88f45a4_THIS_IS_NOT_REAL_973e5a5e2b190370'

alternatively this may be input with the command line argument '-k'
e.g. ./get-otx-iocs.py -k e59df4e88f45a4_THIS_IS_NOT_REAL_973e5a5e2b190370

By default the output will write to /opt/threat_feeds/otx/iocs/ - Review the default file output destination and update to suit your preferences or use the command line argument '-o'
e.g. ./get-otx-iocs.py -o /opt/iocs

Enter a proxy if required for internet access in the get-otx-iocs.py file or alternatively use the command line argument '-p'
e.g. ./get-otx-iocs.py -p http://proxy:8080
or 
./get-otx-iocs.py -p http://user:pass@proxy:8080

the --siem option writes to a CSV file
without this option the destination will be .txt


