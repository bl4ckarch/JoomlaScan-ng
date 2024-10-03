#!/usr/bin/env python3
# File name          : joomlascan-ng.py
# Author             : drego85
#update              : bl4ckarch
# Date created       : 03 oct 2024


import sys
import requests
import argparse
from bs4 import BeautifulSoup
import threading
import time

dbarray = []
url = ""
useragentdesktop = {"User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36",
                    "Accept-Language": "it"}
timeoutconnection = 5
pool = None
swversion = "1.0"


def hello():
    print("--------------------------------------------")
    print("      	    Joomla Scan-ng                 ")
    print("   Usage: python3 joomlascan-ng.py <target> ")
    print("   Version " + swversion + " - Database Entries " + str(len(dbarray)))
    print("    Originally created by Andrea Draghetti  ")
    print("    python3 version by @bl4ckarch           ")
    print("-------------------------------------------")


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
            print(f"\t README file found \t > {url}{path}")


def check_license(url, component):
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
            print(f"\t LICENSE file found \t > {url}{path}")


def check_changelog(url, component):
    changelog_paths = [
        f"/components/{component}/CHANGELOG.txt",
        f"/components/{component}/changelog.txt",
        f"/administrator/components/{component}/CHANGELOG.txt",
        f"/administrator/components/{component}/changelog.txt"
    ]

    for path in changelog_paths:
        if check_url(url, path) == 200:
            print(f"\t CHANGELOG file found \t > {url}{path}")


def check_mainfest(url, component):
    manifest_paths = [
        f"/components/{component}/MANIFEST.xml",
        f"/components/{component}/manifest.xml",
        f"/administrator/components/{component}/MANIFEST.xml",
        f"/administrator/components/{component}/manifest.xml"
    ]

    for path in manifest_paths:
        if check_url(url, path) == 200:
            print(f"\t MANIFEST file found \t > {url}{path}")


def check_index(url, component):
    index_paths = [
        f"/components/{component}/index.htm",
        f"/components/{component}/index.html",
        f"/administrator/components/{component}/INDEX.htm",
        f"/administrator/components/{component}/INDEX.html"
    ]

    for path in index_paths:
        if (check_url_head_content_length(url, path) == '200' and
                int(check_url_head_content_length(url, path) or 0) > 1000):
            print(f"\t INDEX file descriptive found \t > {url}{path}")


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
        print(f"Component found: {component}\t > {url}/index.php?option={component}")

        check_readme(url, component)
        check_license(url, component)
        check_changelog(url, component)
        check_mainfest(url, component)
        check_index(url, component)

        if index_of(url, f"/components/{component}/"):
            print(f"\t Explorable Directory \t > {url}/components/{component}/")

        if index_of(url, f"/administrator/components/{component}/"):
            print(f"\t Explorable Directory \t > {url}/administrator/components/{component}/")

    elif check_url(url, f"/components/{component}/") == 200:
        print(f"Component found: {component}\t > {url}/index.php?option={component}")
        print("\t But possibly it is not active or protected")

        check_readme(url, component)
        check_license(url, component)
        check_changelog(url, component)
        check_mainfest(url, component)
        check_index(url, component)

        if index_of(url, f"/components/{component}/"):
            print(f"\t Explorable Directory \t > {url}/components/{component}/")

        if index_of(url, f"/administrator/components/{component}/"):
            print(f"\t Explorable Directory \t > {url}/administrator/components/{component}/")

    elif check_url(url, f"/administrator/components/{component}/") == 200:
        print(f"Component found: {component}\t > {url}/index.php?option={component}")
        print("\t On the administrator components")

        check_readme(url, component)
        check_license(url, component)
        check_changelog(url, component)
        check_mainfest(url, component)
        check_index(url, component)

        if index_of(url, f"/administrator/components/{component}/"):
            print(f"\t Explorable Directory \t > {url}/administrator/components/{component}/")

    pool.release()


def main(argv):
    load_component()
    hello()

    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-u", "--url", required=True, help="The Joomla URL/domain to scan.")
        parser.add_argument("-t", "--threads", type=int, default=10, help="The number of threads to use (default: 10).")
        parser.add_argument("-v", "--version", action="version", version="%(prog)s " + swversion)
        arguments = parser.parse_args()
    except Exception as e:
        sys.exit(1)

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
        if check_url(url, "/robots.txt") == 200:
            print(f"Robots file found: \t \t > {url}/robots.txt")
        else:
            print("No Robots file found")

        if check_url(url, "/error_log") == 200:
            print(f"Error log found: \t \t > {url}/error_log")
        else:
            print("No Error Log found")

        print(f"\nStart scan...with {concurrentthreads} concurrent threads!")

        for component in dbarray:
            pool.acquire(blocking=True)
            t = threading.Thread(target=scanner, args=(url, component,))
            t.start()

        while threading.active_count() > 1:
            time.sleep(0.1)

        print("End Scanner")

    else:
        print("Site Down, check url please...")


if __name__ == "__main__":
    main(sys.argv[1:])
