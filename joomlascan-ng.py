#!/usr/bin/env python3
# File name          : joomlascan-ng.py
# Author             : drego85
# update             : bl4ckarch
# Date created       : 03 oct 2024

import sys
import requests
import argparse
from bs4 import BeautifulSoup
import threading
import time
import logging


import logging

import logging

class CustomColors:
    # Defining unique color codes for each log level
    DEBUG = '\033[94m'   
    INFO = '\033[92m'    
    VALID = '\033[96m'   
    WARNING = '\033[93m' 
    ERROR = '\033[91m'   
    CRITICAL = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class CustomFormatter(logging.Formatter):
    
    format_dict = {
        logging.DEBUG: CustomColors.DEBUG + "[DEBUG] " + CustomColors.RESET,
        logging.INFO: CustomColors.INFO + "[+][INFO] " + CustomColors.RESET,
        logging.WARNING: CustomColors.WARNING + "[!!!!][WARNING] " + CustomColors.RESET,
        logging.ERROR: CustomColors.ERROR + "[-][ERROR] " + CustomColors.RESET,
        logging.CRITICAL: CustomColors.CRITICAL + "[CRITICAL] " + CustomColors.RESET,
        'VALID': CustomColors.VALID + "[+++][VALID] " + CustomColors.RESET,  # Custom color for VALID
    }

    def format(self, record):
        log_fmt = self.format_dict.get(getattr(record, 'levelname', logging.INFO), self.format_dict.get(record.levelno))
        formatter = logging.Formatter('%(asctime)s ' + log_fmt + '%(message)s', "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


VALID_LEVEL_NUM = 25
logging.addLevelName(VALID_LEVEL_NUM, 'VALID')

def pop_valid(text):
    logging.log(VALID_LEVEL_NUM, text)


handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())

def setup_logging(debug_mode):
    """Set up logging level based on the debug flag."""
    if debug_mode:
        logging.basicConfig(level=logging.DEBUG, handlers=[handler])
    else:
        logging.basicConfig(level=logging.INFO, handlers=[handler])


def pop_err(text):
    logging.error(text)

def pop_dbg(text):
    logging.debug(text)

def pop_info(text):
    logging.info(text)

def pop_warning(text):
    logging.warning(text)

def pop_critical(text):
    logging.critical(text)


dbarray = []
url = ""
useragentdesktop = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36",
    "Accept-Language": "it"
}
timeoutconnection = 5
pool = None
swversion = "1.0"


def banner():
    print("--------------------------------------------")
    print("      	    Joomla Scan-ng                 ")
    print("   Usage: python3 joomlascan-ng.py -u <target> ")
    print("   Version " + swversion + " - Database Entries " + str(len(dbarray)))
    print("    Originally created by Andrea Draghetti  ")
    print("    python3 version by @bl4ckarch           ")
    print("-------------------------------------------")

def check_waf(url):
    # Send a request to the target URL and capture the headers
    try:
        response = requests.get(url)
        headers = response.headers
        source = str(headers)

        waf_detected = False
        pop_warning("Starting WAF Detector...")

        # Check for CloudFlare
        if "cloudflare-nginx" in source or "CF-Chl-Bypass" in source or "cloudflare" in source or "__cfduid" in source:
            pop_warning("Firewall detected: CloudFlare")
            waf_detected = True

        # Check for Incapsula
        elif "incapsula" in source or "incap_ses" in source or "visid_incap" in source:
            pop_warning("Firewall detected: Incapsula")
            waf_detected = True

        # Check for Shieldfy
        elif "ShieldfyWebShield" in source:
            pop_warning("Firewall detected: Shieldfy")
            waf_detected = True

        # Check for Sucuri
        elif "X-Sucuri-ID" in source:
            pop_warning("Firewall detected: Sucuri Firewall (Sucuri Cloudproxy)")
            waf_detected = True

        # Check for Anquanbao
        elif "X-Powered-By-Anquanbao" in source:
            pop_warning("Firewall detected: Anquanbao")
            waf_detected = True

        # Check for Barracuda
        elif "barra_counter_session" in source or "BNI__BARRACUDA_LB_COOKIE" in source or "BNI_persistence" in source:
            pop_warning("Firewall detected: Barracuda Application Firewall")
            waf_detected = True

        # Check for BinarySec
        elif "BinarySec" in source or "x-binarysec-via" in source or "x-binarysec-nocache" in source:
            pop_warning("Firewall detected: BinarySec")
            waf_detected = True

        # Check for BlockDoS
        elif "BlockDos.net" in source:
            pop_warning("Firewall detected: BlockDoS")
            waf_detected = True

        # Check for ChinaCache
        elif "Powered-By-ChinaCache" in source:
            pop_warning("Firewall detected: ChinaCache-CDN")
            waf_detected = True

        # Check for Cisco ACE
        elif "ACE XML Gateway" in source:
            pop_warning("Firewall detected: Cisco ACE XML Gateway")
            waf_detected = True

        # Check for Comodo WAF
        elif "Protected by COMODO WAF" in source:
            pop_warning("Firewall detected: Comodo WAF")
            waf_detected = True

        # Check for Applicure dotDefender
        elif "X-dotDefender-denied" in source:
            pop_warning("Firewall detected: Applicure dotDefender")
            waf_detected = True

        # Check for F5 BIG-IP APM
        elif "BigIP" in source or "BIG-IP" in source or "BIGIP" in source or "LastMRH_Session" in source or "MRHSequence" in source:
            pop_warning("Firewall detected: F5 BIG-IP APM")
            waf_detected = True

        # Check for F5 Trafficshield
        elif "F5-TrafficShield" in source:
            pop_warning("Firewall detected: F5 Trafficshield")
            waf_detected = True

        # Check for FortiWeb
        elif "FORTIWAFSID" in source:
            pop_warning("Firewall detected: FortiWeb")
            waf_detected = True

        # Check for Mission Control Application Shield
        elif "Mission Control Application Shield" in source:
            pop_warning("Firewall detected: Mission Control Application Shield")
            waf_detected = True

        # Check for Naxsi
        elif "naxsi" in source:
            pop_warning("Firewall detected: Naxsi")
            waf_detected = True

        # Check for NetContinuum
        elif "NCI__SessionId" in source:
            pop_warning("Firewall detected: NetContinuum")
            waf_detected = True

        # Check for Citrix NetScaler
        elif "pwcount" in source or "ns_af" in source or "citrix_ns_id" in source or "NSC_" in source:
            pop_warning("Firewall detected: Citrix NetScaler")
            waf_detected = True

        # Check for NSFocus
        elif "NSFocus" in source:
            pop_warning("Firewall detected: NSFocus")
            waf_detected = True

        # Check for PowerCDN
        elif "PowerCDN" in source:
            pop_warning("Firewall detected: PowerCDN")
            waf_detected = True

        # Check for Profense
        elif "profense" in source:
            pop_warning("Firewall detected: Profense")
            waf_detected = True

        # Check for Radware AppWall
        elif "X-SL-CompState" in source:
            pop_warning("Firewall detected: Radware AppWall")
            waf_detected = True

        # Check for Safedog
        elif "Safedog" in source or "safedog" in source:
            pop_warning("Firewall detected: Safedog")
            waf_detected = True

        # Check for Teros WAF
        elif "st8id" in source:
            pop_warning("Firewall detected: Teros WAF")
            waf_detected = True

        # Check for USP Secure Entry Server
        elif "Secure Entry Server" in source:
            pop_warning("Firewall detected: USP Secure Entry Server")
            waf_detected = True

        # Check for Wallarm
        elif "nginx-wallarm" in source:
            pop_warning("Firewall detected: Wallarm")
            waf_detected = True

        # Check for West263CDN
        elif "WT263CDN" in source:
            pop_warning("Firewall detected: West263CDN")
            waf_detected = True

        # Check for 360WangZhanBao
        elif "X-Powered-By-360WZB" in source:
            pop_warning("Firewall detected: 360WangZhanBao")
            waf_detected = True

        # Check for ModSecurity
        modsec_response = requests.get(url + "/../../etc")
        modsec_source = str(modsec_response.headers)
        if "mod_security" in modsec_source or "Mod_Security" in modsec_source or "NOYB" in modsec_source:
            pop_warning("Firewall detected: ModSecurity")
            waf_detected = True

        if not waf_detected:
            pop_valid("No Firewall detected.")

    except Exception as e:
        print(f"Error detecting WAF: {e}")

def missconfig_check(url):
    # List of common misconfigured paths
    configs = ['server-status', 'server-info']
    misconfig_found = False

    pop_info("Checking for misconfigured Apache info/status files...")

    for config in configs:
        try:
            # Build the full URL to the config path
            config_url = f"{url}/{config}"
            # Send a request to the URL
            response = requests.get(config_url)
            source = response.text

            # Check for keywords that indicate the presence of misconfigured files
            if ("Apache Server Information" in source or
                "Server Root" in source or
                "Apache Status" in source):
                pop_valid(f"Interesting file found: {config_url}")
                misconfig_found = True

        except Exception as e:
            pop_critical(f"Error while checking {config}: {e}")

    if not misconfig_found:
        print("Readable info/status files are not found.")

def load_component():
    with open("comptotestdb.txt", "r") as f:
        for line in f:
            dbarray.append(line.strip())


def check_url(url, path="/"):
    fullurl = url + path
    try:
        conn = requests.get(fullurl, headers=useragentdesktop, timeout=timeoutconnection)
        if conn.headers.get("content-length") != "0":
            return conn.status_code
        else:
            return 404
    except Exception:
        return None


def check_url_head_content_length(url, path="/"):
    fullurl = url + path
    try:
        conn = requests.head(fullurl, headers=useragentdesktop, timeout=timeoutconnection)
        return conn.headers.get("content-length")
    except Exception:
        return None


def check_readme(url, component):
    pop_info(f"Checking Readme files")
    readme_paths = [
        f"/components/{component}/README.txt",
        f"/components/{component}/readme.txt",
        f"/components/{component}/README.md",
        f"/components/{component}/readme.md",
        f"/administrator/components/{component}/README.txt",
        f"/administrator/components/{component}/readme.txt",
        f"/administrator/components/{component}/README.md",
        f"/administrator/components/{component}/readme.md"
    ]

    for path in readme_paths:
        if check_url(url, path) == 200:
            pop_valid(f"\t README file found \t > {url}{path}")


def check_license(url, component):
    pop_info(f"Checking license files")
    license_paths = [
        f"/components/{component}/LICENSE.txt",
        f"/components/{component}/license.txt",
        f"/administrator/components/{component}/LICENSE.txt",
        f"/administrator/components/{component}/license.txt",
        f"/components/{component}/{component[4:]}.xml",
        f"/administrator/components/{component}/{component[4:]}.xml"
    ]

    for path in license_paths:
        if check_url(url, path) == 200:
            pop_valid(f"\t LICENSE file found \t > {url}{path}")


def check_changelog(url, component):
    pop_info(f"Checking component directory and files")
    changelog_paths = [
        f"/components/{component}/CHANGELOG.txt",
        f"/components/{component}/changelog.txt",
        f"/administrator/components/{component}/CHANGELOG.txt",
        f"/administrator/components/{component}/changelog.txt"
    ]

    for path in changelog_paths:
        if check_url(url, path) == 200:
            pop_valid(f"\t CHANGELOG file found \t > {url}{path}")


def check_mainfest(url, component):
    pop_info(f"Checking manifest files")
    manifest_paths = [
        f"/components/{component}/MANIFEST.xml",
        f"/components/{component}/manifest.xml",
        f"/administrator/components/{component}/MANIFEST.xml",
        f"/administrator/components/{component}/manifest.xml"
    ]

    for path in manifest_paths:
        if check_url(url, path) == 200:
            pop_valid(f"\t MANIFEST file found \t > {url}{path}")


def check_index(url, component):
    pop_info(f"Checking index files")
    index_paths = [
        f"/components/{component}/index.htm",
        f"/components/{component}/index.html",
        f"/administrator/components/{component}/INDEX.htm",
        f"/administrator/components/{component}/INDEX.html"
    ]

    for path in index_paths:
        if (check_url_head_content_length(url, path) == '200' and
                int(check_url_head_content_length(url, path) or 0) > 1000):
            pop_valid(f"\t INDEX file descriptive found \t > {url}{path}")


def index_of(url, path="/"):
    fullurl = url + path
    try:
        page = requests.get(fullurl, headers=useragentdesktop, timeout=timeoutconnection)
        soup = BeautifulSoup(page.text, "html.parser")
        titlepage = soup.title.string if soup.title else ""
        return "Index of /" in titlepage
    except Exception:
        return False


def scanner(url, component):
    
    if check_url(url, f"/index.php?option={component}") == 200:
        pop_valid(f"Component found: {component}\t > {url}/index.php?option={component}")

        check_readme(url, component)
        check_license(url, component)
        check_changelog(url, component)
        check_mainfest(url, component)
        check_index(url, component)

        if index_of(url, f"/components/{component}/"):
            pop_valid(f"\t Explorable Directory \t > {url}/components/{component}/")

        if index_of(url, f"/administrator/components/{component}/"):
            pop_valid(f"\t Explorable Directory \t > {url}/administrator/components/{component}/")

    elif check_url(url, f"/components/{component}/") == 200:
        pop_valid(f"Component found: {component}\t > {url}/index.php?option={component}")
        pop_warning("\t But possibly it is not active or protected")

        check_readme(url, component)
        check_license(url, component)
        check_changelog(url, component)
        check_mainfest(url, component)
        check_index(url, component)

        if index_of(url, f"/components/{component}/"):
            pop_valid(f"\t Explorable Directory \t > {url}/components/{component}/")

        if index_of(url, f"/administrator/components/{component}/"):
            pop_valid(f"\t Explorable Directory \t > {url}/administrator/components/{component}/")

    elif check_url(url, f"/administrator/components/{component}/") == 200:
        pop_valid(f"Component found: {component}\t > {url}/index.php?option={component}")
        pop_valid("\t On the administrator components")

        check_readme(url, component)
        check_license(url, component)
        check_changelog(url, component)
        check_mainfest(url, component)
        check_index(url, component)

        if index_of(url, f"/administrator/components/{component}/"):
            pop_valid(f"\t Explorable Directory \t > {url}/administrator/components/{component}/")

    pool.release()


def main(argv):
    load_component()
    banner()

    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-u", "--url", required=True, help="The Joomla URL/domain to scan.")
        parser.add_argument("-t", "--threads", type=int, default=10, help="The number of threads to use (default: 10).")
        parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output.")
        parser.add_argument("-v", "--version", action="version", version="%(prog)s " + swversion)
        arguments = parser.parse_args()
    except Exception as e:
        sys.exit(1)

    # Set up logging based on debug flag
    setup_logging(arguments.debug)

    url = arguments.url
    if not (url.startswith("http://") or url.startswith("https://")):
        print("You must insert http:// or https:// protocol\n")
        sys.exit(1)

    if url.endswith("/"):
        url = url[:-1]

    concurrentthreads = arguments.threads
    global pool
    pool = threading.BoundedSemaphore(concurrentthreads)

    if check_url(url) != 404:
        check_waf(url)
        if check_url(url, "/robots.txt") == 200:
            pop_valid(f"Robots file found: \t \t > {url}/robots.txt")
        else:
            pop_dbg("No Robots file found")

        if check_url(url, "/error_log") == 200:
            pop_info(f"Error log found: \t \t > {url}/error_log")
        else:
            pop_dbg("No Error Log found")

        pop_warning(f"Start scan...with {concurrentthreads} concurrent threads!")

        for component in dbarray:
            pool.acquire(blocking=True)
            t = threading.Thread(target=scanner, args=(url, component,))
            t.start()

        while threading.active_count() > 1:
            time.sleep(0.1)

        pop_dbg("End Scanner")

    else:
        pop_err("Site Down, check url please...")


if __name__ == "__main__":
    main(sys.argv[1:])
