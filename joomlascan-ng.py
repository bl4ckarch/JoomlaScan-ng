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
import xml.etree.ElementTree as ET
import base64
import webbrowser
from datetime import datetime
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from urllib3.util.ssl_ import create_urllib3_context

class CustomColors:
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
        'VALID': CustomColors.VALID + "[+++][VALID] " + CustomColors.RESET,  
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

class SSLAdapter(HTTPAdapter):
    """
    A TransportAdapter that allows us to tweak the SSL settings to support weak ciphers
    or lower security levels.
    """
    def __init__(self, ssl_options=None, *args, **kwargs):
        self.ssl_options = ssl_options
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        if self.ssl_options:
            context.options |= self.ssl_options  
        self.poolmanager = PoolManager(*args, ssl_context=context, **kwargs)

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
    print("""
   __                        _         __                                   
   \ \  ___   ___  _ __ ___ | | __ _  / _\ ___ __ _ _ __        _ __   __ _ 
    \ \/ _ \ / _ \| '_ ` _ \| |/ _` | \ \ / __/ _` | '_ \ _____| '_ \ / _` |
 /\_/ / (_) | (_) | | | | | | | (_| | _\ \ (_| (_| | | | |_____| | | | (_| |
 \___/ \___/ \___/|_| |_| |_|_|\__,_| \__/\___\__,_|_| |_|     |_| |_|\__, |
                                                                      |___/ 
    """)
    print("--------------------------------------------")
    print("      	    Joomla Scan-ng                 ")
    print("   Usage: python3 joomlascan-ng.py -u <target> ")
    print("   Version " + swversion + " - Database Entries " + str(len(dbarray)))
    print("    Originally created by Andrea Draghetti  ")
    print("    python3 version by @bl4ckarch           ")
    ("-------------------------------------------")

def is_url_accessible(url, proxy=None):
    """
    Check if the URL is accessible with lower SSL security settings for weak DH keys.
    Return True if the URL returns a 200 OK status, else False.
    """
    try:
        session = requests.Session()
        ssl_options = ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        session.mount('https://', SSLAdapter(ssl_options=ssl.OP_SINGLE_DH_USE))
        
       
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        response = session.get(url, timeout=timeoutconnection, verify=False, proxies=proxies)
        if response.status_code == 200:
            pop_valid(f"URL {url} is accessible.")
            return True
        else:
            pop_err(f"URL {url} is not accessible. Status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        pop_err(f"Error connecting to {url}: {e}")
        return False

def check_waf(url, proxy=None):    
    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        response = requests.get(url, verify=False, proxies=proxies)
        headers = response.headers
        source = str(headers)

        waf_detected = False
        pop_warning("Starting WAF Detector...")

        if "cloudflare-nginx" in source or "CF-Chl-Bypass" in source or "cloudflare" in source or "__cfduid" in source:
            pop_warning("Firewall detected: CloudFlare")
            waf_detected = True

        
        elif "incapsula" in source or "incap_ses" in source or "visid_incap" in source:
            pop_warning("Firewall detected: Incapsula")
            waf_detected = True

        
        elif "ShieldfyWebShield" in source:
            pop_warning("Firewall detected: Shieldfy")
            waf_detected = True

        
        elif "X-Sucuri-ID" in source:
            pop_warning("Firewall detected: Sucuri Firewall (Sucuri Cloudproxy)")
            waf_detected = True

        
        elif "X-Powered-By-Anquanbao" in source:
            pop_warning("Firewall detected: Anquanbao")
            waf_detected = True

        
        elif "barra_counter_session" in source or "BNI__BARRACUDA_LB_COOKIE" in source or "BNI_persistence" in source:
            pop_warning("Firewall detected: Barracuda Application Firewall")
            waf_detected = True

        
        elif "BinarySec" in source or "x-binarysec-via" in source or "x-binarysec-nocache" in source:
            pop_warning("Firewall detected: BinarySec")
            waf_detected = True

        
        elif "BlockDos.net" in source:
            pop_warning("Firewall detected: BlockDoS")
            waf_detected = True

        
        elif "Powered-By-ChinaCache" in source:
            pop_warning("Firewall detected: ChinaCache-CDN")
            waf_detected = True

        
        elif "ACE XML Gateway" in source:
            pop_warning("Firewall detected: Cisco ACE XML Gateway")
            waf_detected = True

        
        elif "Protected by COMODO WAF" in source:
            pop_warning("Firewall detected: Comodo WAF")
            waf_detected = True

        
        elif "X-dotDefender-denied" in source:
            pop_warning("Firewall detected: Applicure dotDefender")
            waf_detected = True

        
        elif "BigIP" in source or "BIG-IP" in source or "BIGIP" in source or "LastMRH_Session" in source or "MRHSequence" in source:
            pop_warning("Firewall detected: F5 BIG-IP APM")
            waf_detected = True

        
        elif "F5-TrafficShield" in source:
            pop_warning("Firewall detected: F5 Trafficshield")
            waf_detected = True

        
        elif "FORTIWAFSID" in source:
            pop_warning("Firewall detected: FortiWeb")
            waf_detected = True

        
        elif "Mission Control Application Shield" in source:
            pop_warning("Firewall detected: Mission Control Application Shield")
            waf_detected = True

        
        elif "naxsi" in source:
            pop_warning("Firewall detected: Naxsi")
            waf_detected = True

        
        elif "NCI__SessionId" in source:
            pop_warning("Firewall detected: NetContinuum")
            waf_detected = True

        
        elif "pwcount" in source or "ns_af" in source or "citrix_ns_id" in source or "NSC_" in source:
            pop_warning("Firewall detected: Citrix NetScaler")
            waf_detected = True

        
        elif "NSFocus" in source:
            pop_warning("Firewall detected: NSFocus")
            waf_detected = True

    
        elif "PowerCDN" in source:
            pop_warning("Firewall detected: PowerCDN")
            waf_detected = True

        
        elif "profense" in source:
            pop_warning("Firewall detected: Profense")
            waf_detected = True

        
        elif "X-SL-CompState" in source:
            pop_warning("Firewall detected: Radware AppWall")
            waf_detected = True

        elif "Safedog" in source or "safedog" in source:
            pop_warning("Firewall detected: Safedog")
            waf_detected = True

        elif "st8id" in source:
            pop_warning("Firewall detected: Teros WAF")
            waf_detected = True

        elif "Secure Entry Server" in source:
            pop_warning("Firewall detected: USP Secure Entry Server")
            waf_detected = True

        elif "nginx-wallarm" in source:
            pop_warning("Firewall detected: Wallarm")
            waf_detected = True

        elif "WT263CDN" in source:
            pop_warning("Firewall detected: West263CDN")
            waf_detected = True

        elif "X-Powered-By-360WZB" in source:
            pop_warning("Firewall detected: 360WangZhanBao")
            waf_detected = True

        modsec_response = requests.get(url + "/../../etc")
        modsec_source = str(modsec_response.headers)
        if "mod_security" in modsec_source or "Mod_Security" in modsec_source or "NOYB" in modsec_source:
            pop_warning("Firewall detected: ModSecurity")
            waf_detected = True

        if not waf_detected:
            pop_valid("No Firewall detected.")

    except Exception as e:
        pop_err(f"Error detecting WAF: {e}")

def check_misconfig(url, proxy=None):
    configs = ['server-status', 'server-info']
    misconfig_found = False

    pop_info("Checking for misconfigured Apache info/status files...")

     
    proxies = {"http": proxy, "https": proxy} if proxy else None

    for config in configs:
        try:
            config_url = f"{url}/{config}"
            
            response = requests.get(config_url, proxies=proxies, timeout=timeoutconnection)
            source = response.text
            if ("Apache Server Information" in source or
                "Server Root" in source or
                "Apache Status" in source):
                pop_valid(f"Interesting file found: {config_url}")
                misconfig_found = True

        except Exception as e:
            pop_critical(f"Error while checking {config}: {e}")

    if not misconfig_found:
        pop_warning("Readable info/status files are not found.")

def check_backup_files(url, proxy=None):
    backup_files = [
        '1.txt', '2.txt', '1.gz', '1.rar', '1.save', '1.tar', '1.tar.bz2', '1.tar.gz', '1.tgz', '1.tmp', '1.zip',
        '2.back', '2.backup', '2.gz', '2.rar', '2.save', '2.tar', '2.tar.bz2', '2.tar.gz', '2.tgz', '2.tmp', '2.zip',
        'backup.back', 'backup.backup', 'backup.bak', 'backup.bck', 'backup.bkp', 'backup.copy', 'backup.gz',
        'backup.old', 'backup.orig', 'backup.rar', 'backup.sav', 'backup.save', 'backup.sql~', 'backup.sql.back',
        'backup.sql.backup', 'backup.sql.bak', 'backup.sql.bck', 'backup.sql.bkp', 'backup.sql.copy', 'backup.sql.gz',
        'backup.sql.old', 'backup.sql.orig', 'backup.sql.rar', 'backup.sql.sav', 'backup.sql.save', 'backup.sql.tar',
        'backup.sql.tar.bz2', 'backup.sql.tar.gz', 'backup.sql.tgz', 'backup.sql.tmp', 'backup.sql.txt', 'backup.sql.zip',
        'backup.tar', 'backup.tar.bz2', 'backup.tar.gz', 'backup.tgz', 'backup.txt', 'backup.zip', 'database.back',
        'database.backup', 'database.bak', 'database.bck', 'database.bkp', 'database.copy', 'database.gz', 'database.old',
        'database.orig', 'database.rar', 'database.sav', 'database.save', 'database.sql~', 'database.sql.back',
        'database.sql.backup', 'database.sql.bak', 'database.sql.bck', 'database.sql.bkp', 'database.sql.copy',
        'database.sql.gz', 'database.sql.old', 'database.sql.orig', 'database.sql.rar', 'database.sql.sav', 'database.sql.save',
        'database.sql.tar', 'database.sql.tar.bz2', 'database.sql.tar.gz', 'database.sql.tgz', 'database.sql.tmp',
        'database.sql.txt', 'database.sql.zip', 'joom.back', 'joom.backup', 'joom.bak', 'joom.bck', 'joom.bkp', 'joom.copy',
        'joom.gz', 'joomla.back', 'joomla.backup', 'joomla.bak', 'joomla.bck', 'joomla.bkp', 'joomla.copy', 'joomla.gz',
        'joomla.old', 'joomla.orig', 'joomla.rar', 'joomla.sav', 'joomla.save', 'joomla.tar', 'joomla.tar.bz2', 'joomla.tar.gz',
        'joomla.tgz', 'joomla.zip', 'site.back', 'site.backup', 'site.bak', 'site.bck', 'site.bkp', 'site.copy', 'site.gz',
        'site.old', 'site.orig', 'site.rar', 'site.sav', 'site.save', 'site.tar', 'site.tar.bz2', 'site.tar.gz', 'site.tgz',
        'site.zip'
    ]

    backup_found = False
    pop_info("Finding common backup files...")

    proxies = {"http": proxy, "https": proxy} if proxy else None

    for backup_file in backup_files:
        try:
            backup_url = f"{url}/{backup_file}"
            
            response = requests.head(backup_url, proxies=proxies, timeout=timeoutconnection)

            if response.status_code == 200 and 'text/html' not in response.headers.get('Content-Type', ''):
                pop_valid(f"Backup file found: {backup_url}")
                backup_found = True

        except Exception as e:
            pop_critical(f"Error while checking {backup_file}: {e}")

    if not backup_found:
        pop_info("No backup files found.")

def check_config_files(url, proxy=None):
    config_files = [
        'configuration.php_old', 'configuration.php_new', 'configuration.php~', 'configuration.php.new', 'configuration.php.new~',
        'configuration.php.old', 'configuration.php.old~', 'configuration.bak', 'configuration.php.bak', 'configuration.php.bkp',
        'configuration.txt', 'configuration.php.txt', 'configuration - Copy.php', 'configuration.php.swo', 'configuration.php_bak',
        'configuration.php#', 'configuration.orig', 'configuration.php.save', 'configuration.php.original', 'configuration.php.swp',
        'configuration.save', '.configuration.php.swp', 'configuration.php1', 'configuration.php2', 'configuration.php3',
        'configuration.php4', 'configuration.php6', 'configuration.php7', 'configuration.phtml', 'configuration.php-dist'
    ]

    config_found = False
    sensitive_keywords = ['public $ftp_pass', '$dbtype', 'force_ssl', 'mosConfig_secret', 'mosConfig_dbprefix']
    
    pop_info("Checking for sensitive config.php files...")

    proxies = {"http": proxy, "https": proxy} if proxy else None

    for config_file in config_files:
        try:
            config_url = f"{url}/{config_file}"
            
            response = requests.get(config_url, proxies=proxies, timeout=timeoutconnection)

            if response.status_code == 200:
                for keyword in sensitive_keywords:
                    if keyword in response.text:
                        pop_valid(f"Readable config file found: {config_url}")
                        config_found = True
                        break

        except Exception as e:
            pop_critical(f"Error while checking {config_file}: {e}")

    if not config_found:
        pop_warning("No readable config files found.")

def extract_joomla_version_from_site(url, proxy=None):
    """
    Fetch and parse the Joomla version from various XML files hosted on the target site.
    """
    endpoints = [
        'administrator/manifests/files/joomla.xml',
        'language/en-GB/en-GB.xml',
        'administrator/components/com_content/content.xml',
        'administrator/components/com_plugins/plugins.xml',
        'administrator/components/com_media/media.xml',
        'mambots/content/moscode.xml'
    ]

    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    for endpoint in endpoints:
        try:
            joomla_xml_url = f"{url}/{endpoint}"
            response = requests.get(joomla_xml_url, proxies=proxies)

            if response.status_code == 200:
                root = ET.fromstring(response.content)
                version_tag = root.find('version')
                if version_tag is not None:
                    pop_valid(f"Joomla version found in {endpoint}: {version_tag.text.strip()}")
                    return version_tag.text.strip()
                else:
                    pop_warning(f"Version tag not found in {endpoint}")
            else:
                pop_warning(f"Failed to retrieve {endpoint}. HTTP Status Code: {response.status_code}")

        except Exception as e:
            pop_warning(f"Error fetching or parsing {endpoint}: {e}")

    pop_warning("Failed to find Joomla version from the provided endpoints.")
    return None



def core_joomla_vulnerability_check(ver, url, db_path, vulnerabilities):
    try:
        with open(f"{db_path}/corevul.txt", "r") as db_file:
            vver = ver[:6].replace(" ", "")  
            vvtf = False

            pop_info("Core Joomla Vulnerability")

            for row in db_file:
                row = row.strip()  
                fv = row.split('|')[0]  
                fd = row.split('|')[1]  
                sbug = fv.split(',')

                for bs in sbug:
                    if (vver.lower() in bs.lower()) and (vver[0] == bs[0]):
                        fd = fd.replace('$target', url)  
                        fd = fd.replace('\\n', '\r\n')  
                        fd = fd.replace('|', '\r\n\r\n')  

                        
                        vulnerabilities.append({
                            "title": f"Vulnerability affecting Joomla {vver}",  
                            "details": fd  
                        })

                        vvtf = True
                        break

            if vvtf:
                pop_valid("\n".join(vul['details'] for vul in vulnerabilities))
            else:
                pop_info("Target Joomla core is not vulnerable")

    except Exception as e:
        pop_critical(f"Error: {e}")

def do_report(url, joomla_version, start_time, finish_time, vulnerabilities, findings, file_type='html'):
    output_file = f"{url.replace('http://', '').replace('https://', '').replace('/', '_')}_{datetime.now().strftime('%Y%m%d')}.{file_type}"
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Joomla Scan Report</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                background-color: #f5f5f5;
                color: #333;
                margin: 0;
                padding: 20px;
            }}
            h1 {{
                background-color: #003366;
                color: white;
                padding: 15px;
                text-align: center;
                border-radius: 8px;
            }}
            h2 {{
                color: #003366;
                border-bottom: 2px solid #003366;
                padding-bottom: 5px;
                margin-top: 30px;
            }}
            p {{
                line-height: 1.6;
            }}
            .container {{
                max-width: 1000px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            }}
            .vulnerabilities, .findings {{
                margin-top: 20px;
            }}
            .vulnerability-item, .finding-item {{
                background-color: #f9f9f9;
                margin-bottom: 10px;
                padding: 10px;
                border-left: 5px solid #ff6666;
                border-radius: 5px;
            }}
            .vulnerability-item h3, .finding-item h3 {{
                color: #e60000;
                margin: 0;
            }}
            .finding-item h3 {{
                color: red;  /* Ensure component found messages are styled in red */
            }}
            .finding-item {{
                border-left-color: #66cc66;
            }}
            .meta-info {{
                margin-bottom: 20px;
            }}
            .meta-info p {{
                margin: 0;
            }}
            .meta-info strong {{
                color: #003366;
            }}
            .footer {{
                text-align: center;
                margin-top: 40px;
                font-size: 0.9em;
                color: #777;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Joomla Scan Report for {url}</h1>

            <div class="meta-info">
                <p><strong>Joomla Version:</strong> {joomla_version}</p>
                <p><strong>Scan started at:</strong> {start_time}</p>
                <p><strong>Scan finished at:</strong> {finish_time}</p>
            </div>

            <div class="vulnerabilities">
                <h2>Vulnerabilities</h2>
    """

    for vulnerability in vulnerabilities:
        if isinstance(vulnerability, dict):
            html_template += f"""
            <div class="vulnerability-item">
                <h3>{vulnerability['title']}</h3>
                <p>{vulnerability['details']}</p>
            </div>
            """
        else:
            html_template += f"""
            <div class="vulnerability-item">
                <p>{vulnerability}</p>
            </div>
            """

    html_template += """
            </div>
            <div class="findings">
                <h2>Findings</h2>
    """

    for finding in findings:
        if isinstance(finding, dict):
            html_template += f"""
            <div class="finding-item">
                <h3>{finding['description']}</h3>
                <p>{finding['details']}</p>
            </div>
            """
        else:
            html_template += f"""
            <div class="finding-item">
                <p>{finding}</p>
            </div>
            """

    html_template += f"""
            </div>
        </div>
        <div class="footer">
            <p>Report generated by JoomlaScan-ng on {finish_time}</p>
        </div>
    </body>
    </html>
    """

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_template)

    pop_valid(f"Report successfully written to '{output_file}'")

    if file_type == 'html':
        webbrowser.open(output_file)



def load_component():
    with open("comptotestdb.txt", "r") as f:
        for line in f:
            dbarray.append(line.strip())


def check_url(url, path="/", proxy=None):
    fullurl = url + path
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        conn = requests.get(fullurl, headers=useragentdesktop, timeout=timeoutconnection, proxies=proxies)
        if conn.headers.get("content-length") != "0":
            return conn.status_code
        else:
            return 404
    except Exception:
        return None



def check_url_head_content_length(url, path="/", proxy=None):
    fullurl = url + path
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        conn = requests.head(fullurl, headers=useragentdesktop, timeout=timeoutconnection, proxies=proxies)
        return conn.headers.get("content-length")
    except Exception:
        return None



def check_readme(url, component, findings, proxy=None):
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

    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    for path in readme_paths:
        if check_url(url, path, proxy) == 200:
            finding = {
                "description": f"README file found > {url}{path}",
                "details": "This file may contain sensitive information about the component."
            }
            pop_valid(finding["description"])
            findings.append(finding)



def check_license(url, component, findings, proxy=None):
    pop_info(f"Checking license files")
    license_paths = [
        f"/components/{component}/LICENSE.txt",
        f"/components/{component}/license.txt",
        f"/administrator/components/{component}/LICENSE.txt",
        f"/administrator/components/{component}/license.txt",
        f"/components/{component}/{component[4:]}.xml",
        f"/administrator/components/{component}/{component[4:]}.xml"
    ]

    proxies = {"http": proxy, "https": proxy} if proxy else None

    for path in license_paths:
        if check_url(url, path, proxy) == 200:
            finding = {
                "description": f"LICENSE file found > {url}{path}",
                "details": "This file may provide insight into the component's licensing details."
            }
            pop_valid(finding["description"])
            findings.append(finding)



def check_changelog(url, component, findings, proxy=None):
    pop_info(f"Checking changelog files")
    changelog_paths = [
        f"/components/{component}/CHANGELOG.txt",
        f"/components/{component}/changelog.txt",
        f"/administrator/components/{component}/CHANGELOG.txt",
        f"/administrator/components/{component}/changelog.txt"
    ]

    proxies = {"http": proxy, "https": proxy} if proxy else None

    for path in changelog_paths:
        if check_url(url, path, proxy) == 200:
            finding = {
                "description": f"CHANGELOG file found > {url}{path}",
                "details": "This file may contain information about updates and fixes."
            }
            pop_valid(finding["description"])
            findings.append(finding)



def check_mainfest(url, component, findings, proxy=None):
    pop_info(f"Checking manifest files")
    manifest_paths = [
        f"/components/{component}/MANIFEST.xml",
        f"/components/{component}/manifest.xml",
        f"/administrator/components/{component}/MANIFEST.xml",
        f"/administrator/components/{component}/manifest.xml"
    ]

    proxies = {"http": proxy, "https": proxy} if proxy else None

    for path in manifest_paths:
        if check_url(url, path, proxy) == 200:
            finding = {
                "description": f"MANIFEST file found > {url}{path}",
                "details": "This file may contain important metadata about the component."
            }
            pop_valid(finding["description"])
            findings.append(finding)



def check_index(url, component, findings, proxy=None):
    pop_info(f"Checking index files")
    index_paths = [
        f"/components/{component}/index.htm",
        f"/components/{component}/index.html",
        f"/administrator/components/{component}/INDEX.htm",
        f"/administrator/components/{component}/INDEX.html"
    ]

    proxies = {"http": proxy, "https": proxy} if proxy else None

    for path in index_paths:
        content_length = check_url_head_content_length(url, path, proxy)
        if content_length == '200' and int(content_length or 0) > 1000:
            finding = {
                "description": f"INDEX file descriptive found > {url}{path}",
                "details": "This INDEX file is larger than 1000 bytes, indicating that it might contain significant content."
            }
            pop_valid(finding["description"])
            findings.append(finding)


            



def index_of(url, path="/"):
    fullurl = url + path
    try:
        page = requests.get(fullurl, headers=useragentdesktop, timeout=timeoutconnection)
        soup = BeautifulSoup(page.text, "html.parser")
        titlepage = soup.title.string if soup.title else ""
        return "Index of /" in titlepage
    except Exception:
        return False


def scanner(url, component, findings, proxy=None):
    if check_url(url, f"/index.php?option={component}", proxy) == 200:
        finding = f"Component found: {component} > {url}/index.php?option={component}"
        findings.append({
            "description": f"Component found: {component} > {url}/components/{component}/",
            "details": "Component directory is accessible and contains files"
        })

        check_readme(url, component, findings, proxy)
        check_license(url, component, findings, proxy)
        check_changelog(url, component, findings, proxy)
        check_mainfest(url, component, findings, proxy)
        check_index(url, component, findings, proxy)

        if index_of(url, f"/components/{component}/"):
            pop_valid(f"\t Explorable Directory \t > {url}/components/{component}/")
            findings.append({
                "description": f"Explorable Directory > {url}/components/{component}/",
                "details": "Directory is accessible and contains files"
            })

        if index_of(url, f"/administrator/components/{component}/"):
            pop_valid(f"\t Explorable Directory \t > {url}/administrator/components/{component}/")
            findings.append({
                "description": f"Explorable Directory > {url}/administrator/components/{component}/",
                "details": "Administrator directory is accessible"
            })

    elif check_url(url, f"/components/{component}/", proxy) == 200:
        pop_valid(f"Component found: {component} > {url}/components/{component}/")
        findings.append({
            "description": f"Component found: {component} > {url}/components/{component}/",
            "details": "Component directory is accessible and contains files"
        })
        pop_warning("\t But possibly it is not active or protected")

        check_readme(url, component, findings, proxy)
        check_license(url, component, findings, proxy)
        check_changelog(url, component, findings, proxy)
        check_mainfest(url, component, findings, proxy)
        check_index(url, component, findings, proxy)

        if index_of(url, f"/components/{component}/"):
            pop_valid(f"Explorable Directory > {url}/components/{component}/")
            findings.append({
                "description": f"Explorable Directory > {url}/components/{component}/",
                "details": "Directory is accessible and contains files"
            })

        if index_of(url, f"/administrator/components/{component}/"):
            pop_valid(f"\t Explorable Directory \t > {url}/administrator/components/{component}/")
            findings.append({
                "description": f"Explorable Directory > {url}/administrator/components/{component}/",
                "details": "Administrator directory is accessible"
            })

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
        parser.add_argument("-P", "--proxy", help="Send requests through a proxy (e.g., http://127.0.0.1:8080).")
        arguments = parser.parse_args()
    except Exception as e:
        sys.exit(1)

    setup_logging(arguments.debug)

    url = arguments.url
    proxy = arguments.proxy  

    if not (url.startswith("http://") or url.startswith("https://")):
        pop_err("You must insert http:// or https:// protocol\n")
        sys.exit(1)

    if url.endswith("/"):
        url = url[:-1]

    if not is_url_accessible(url, proxy):  
        pop_err("The target URL is not accessible. Exiting...")
        sys.exit(1)

    if extract_joomla_version_from_site(url, proxy) is None:  
        pop_err("The target is not a Joomla website. Exiting...")
        sys.exit(1)

    concurrentthreads = arguments.threads
    global pool
    pool = threading.BoundedSemaphore(concurrentthreads)

    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    vulnerabilities = []
    findings = []

    
    if check_url(url, path="/", proxy=proxy) != 404:
        check_waf(url, proxy)
        check_misconfig(url, proxy)
        check_backup_files(url, proxy)
        check_config_files(url, proxy)

        joomla_version = extract_joomla_version_from_site(url, proxy)
        db_path = "./db"
        if joomla_version:
            pop_info(f"Detected Joomla version: {joomla_version}")
            core_joomla_vulnerability_check(joomla_version, url, db_path, vulnerabilities)
        else:
            pop_critical("Failed to extract Joomla version.")

        if check_url(url, "/robots.txt", proxy) == 200:
            pop_valid(f"Robots file found: \t \t > {url}/robots.txt")
        else:
            pop_dbg("No Robots file found")

        if check_url(url, "/error_log", proxy) == 200:
            pop_info(f"Error log found: \t \t > {url}/error_log")
        else:
            pop_dbg("No Error Log found")

        pop_warning(f"Start scan...with {concurrentthreads} concurrent threads!")

        for component in dbarray:
            pool.acquire(blocking=True)
            t = threading.Thread(target=scanner, args=(url, component, findings, proxy))  # Pass proxy
            t.start()

        while threading.active_count() > 1:
            time.sleep(0.1)

        pop_dbg("End Scanner")
        finish_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        do_report(url, joomla_version, start_time, finish_time, vulnerabilities=vulnerabilities, findings=findings, file_type='html')
    else:
        pop_err("Site Down, check url please...")


if __name__ == "__main__":
    main(sys.argv[1:])
