import requests
import re
import json
import os
import base64
import logging
import sys
import concurrent.futures
from django.core.cache import caches
import time
import validators
from django.utils import timezone
from analytics.models import IpLookup, DomainLookup, UrlLookup, UserAgentLookup, Source, HashLookup
from analytics.normalize import normalize_ip, normalize_domain, normalize_url, normalize_user_agent
from uuid import uuid4
from django.db import connections


logging.basicConfig(stream=sys.stdout, 
                    level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set up Redis cache for AbuseIPDB
abuse_cache = caches['abuseipdb']
# Set up Redis cache for VirusTotal
virustotal_cache = caches['virustotal']
# Set up Redis cache for Big Data
bigdata_cache = caches['bigdata']
# Define a cache timeout
# This is the time in seconds that the cache will hold the data before it expires
CACHE_TTL = 86400  # 24 hours

# Set HTTP content type for requests
CONTENT_TYPE = 'application/json'

# Replace these with your actual API keys and secure them appropriately
ABUSEIPDB_KEYS = [
    os.environ.get('ABUSEIPDB_KEY', None),
    os.environ.get('ABUSEIPDB_KEY1', None),
    os.environ.get('ABUSEIPDB_KEY2', None)
]

ABUSEIPDB_KEYS = [key for key in ABUSEIPDB_KEYS if key is not None]

# Counter to keep track of the request number
request_counter = 0

VIRUSTOTAL_KEY = os.environ.get('VIRUSTOTAL_KEY', None)
IBM_XFORCE_KEY = os.environ.get('IBM_XFORCE_KEY', None)
IBM_XFORCE_PASSWORD = os.environ.get('IBM_XFORCE_PASSWORD', None)
BIG_DATA_USERAGENT_KEY = os.environ.get('BIG_DATA_USERAGENT_KEY', None)

categories_data = {}
country_codes_dict = {}

def get_api_key():
    global request_counter
    api_key = ABUSEIPDB_KEYS[request_counter % len(ABUSEIPDB_KEYS)]
    request_counter += 1
    return api_key

def load_global_data():
    # Assuming you have categories.json and country_codes.json in your Django settings directory or a similar secure place
    
    global categories_data, country_codes_dict
    try:
        with open('app/config_files/categories.json', 'r') as file:
            categories_data = {int(k): v for k, v in json.load(file).items()}
        with open('app/config_files/country_codes.json', 'r') as file:
            country_codes_dict = json.load(file)
        logger.info("Successfully loaded global data")
    except Exception as e:
        logger.error(f"Failed to load global data: {e}")

load_global_data()

# Function to extract IP addresses from a given data string
def extract_ips(data):
    return re.findall(r'(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Fa-f0-9]{1,4}:+)+[A-Fa-f0-9]{0,4}', data)

def check_ip_on_abuse_ipdb(abuse_ipdb_key, country_codes_dict, ip):
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': abuse_ipdb_key,
            'Accept': CONTENT_TYPE,
            'Content-Type': CONTENT_TYPE
        }

        params = {
            'ipAddress': ip,
            'maxAgeInDays': '30',
        }
        # logging.info(f"Requesting AbuseIPDB check for IP: {ip}")
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json().get("data")
            countrycode = data.get("countryCode")
            isp = data.get("isp")
            total_reports = data.get("totalReports")
            abuseconfidencescore = data.get("abuseconfidencescore")
            try:
                iswhitelisted = data.get("isWhitelisted")
                if iswhitelisted is None:
                    iswhitelisted = "False"
            except Exception as e:
                iswhitelisted = "False"
                logger.error(f"Error checking if IP {ip} is whitelisted: {e}")
            country = country_codes_dict.get(countrycode)
        else: 
            logger.error(f"Failed to fetch data for IP {ip}. Status code: {response.status_code}")
        return country, isp, total_reports, abuseconfidencescore, iswhitelisted

def check_reports_on_abuse_ipdb(abuse_ipdb_key, ip):
    global categories_data
    url = 'https://api.abuseipdb.com/api/v2/reports'
    headers = {
        'Key': abuse_ipdb_key,
        'Accept': CONTENT_TYPE,
        'Content-Type': CONTENT_TYPE
    }

    params = {
        'ipAddress': ip,
        'maxAgeInDays': '30',
        'perPage':'1'
    }
    translated_category = "Unknown Category"
    reported_at = "Unknown Date"
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json().get("data")
        category = data.get('results', [{}])[0].get('categories', [])[0]
        reported_at = data.get('results', [{}])[0].get('reportedAt')
        if category in categories_data:
            translated_category = categories_data[category]
        else:
            logger.error(f"Report Category not found for IP {ip}")
    else:
        logger.error(f"Failed to fetch data for IP {ip}. Status code: {response.status_code}")
    return translated_category, reported_at


def build_output_line(ip, abuse_ipdb_key, country_codes_dict):
    # Your existing calls (unchanged)
    country, isp, total_reports, abuseconfidencescore, iswhitelisted = check_ip_on_abuse_ipdb(
        abuse_ipdb_key, country_codes_dict, ip
    )
    
    output_line = f"{ip} ({country}, {isp}) "
    
    if (total_reports or 0) >= 1:
        translated_category, reported_at = check_reports_on_abuse_ipdb(abuse_ipdb_key, ip)
        output_line += f"Reported for {translated_category} at {reported_at}"
    else:
        output_line += "No reports"

    output_line += f" | Abuse Confidence Score: {abuseconfidencescore} | Is Whitelisted: {iswhitelisted}"
    return output_line

def get_output_line_with_cache(ip, abuse_ipdb_key, country_codes_dict):
    key = f"abuseipdb:line:{ip}"
    cached_line = abuse_cache.get(key)
    if cached_line is not None:
        return cached_line

    # Not cached → build and cache
    line = build_output_line(ip, abuse_ipdb_key, country_codes_dict)
    abuse_cache.set(key, line, CACHE_TTL)
    return line

def abuse_ipdb_logic(ips_to_check):
    abuse_ipdb_key = get_api_key()
    global categories_data, country_codes_dict  # keeping your globals

    ip_info = []

    def process_ip(ip):
        try:
            return get_output_line_with_cache(ip, abuse_ipdb_key, country_codes_dict)
        except Exception as e:
            logger.exception("Error while processing IP %s", ip)
            return f"Error requesting the IP {ip}: {e}"

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_ip, ip) for ip in ips_to_check]
        for future in concurrent.futures.as_completed(futures):
            ip_info.append(future.result())

    return ip_info


def check_ip_on_virustotal(ip):
    virus_key = VIRUSTOTAL_KEY
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
    "accept": CONTENT_TYPE,
    "x-apikey": f"{virus_key}"
    }
    response = requests.get(url, headers=headers)
    logger.info(f"Requesting VirusTotal check for IP: {ip}")

    if response.status_code == 200:
        data = response.json().get("data")
        isp = data.get("attributes").get("as_owner")
        countrycode = data.get("attributes").get("rdap").get("country")
        malicious_count = data.get("attributes").get("last_analysis_stats").get("malicious")
    else:
        logger.error(f"Failed to fetch reports for IP {ip}. Status code: {response.status_code}")
        logger.error(f"Failed to fetch data for IP {ip}. Status code: {response.status_code}")  
    return countrycode, isp, malicious_count

def get_virustotal_ip_output_line_with_cache(ip):
    key = f"virustotal:line:{ip}"
    cached_line = virustotal_cache.get(key)
    if cached_line is not None:
        logger.info(f"Cache found for IP {ip}")
        return cached_line
    else:
        logger.info(f"Cache miss for IP {ip}, fetching from VirusTotal")

    # Not cached → build and cache
    country, isp, malicious_count = check_ip_on_virustotal(ip)
    output_line = f"{ip} ({country}, {isp}) "
    
    if malicious_count >= 1:
        output_line += f"On VirusTotal {malicious_count} security vendors flagged this IP address as malicious"
    else:
        output_line += "No reports on VirusTotal"
    virustotal_cache.set(key, output_line, CACHE_TTL)
    return output_line

def virustotal_logic(ips_to_check):
    logger.info("Starting virustotal_logic")
    ip_info = []
    
    for ip in ips_to_check:
        try:
            output_line = get_virustotal_ip_output_line_with_cache(ip)
            ip_info.append(output_line)
        except Exception as e:
            ip_info.append(f"Error requesting the IP {ip}")
            logger.error(f"Error requesting the IP {ip}: {e}")
    return ip_info

def extract_domains(data):
    # Split the input by lines and strip any surrounding whitespace
    domains = [line.strip() for line in data.splitlines() if line.strip()]
    return domains

def check_domain_in_virustotal(domain):
    if validators.domain(domain):
        logger.info(f"Domain {domain} is valid")
        key = f"virustotal:line:{domain}"
        cached_line = virustotal_cache.get(key)
        if cached_line is not None:
            logger.info(f"Cache found for Domain {domain}")
            return cached_line
        else:
            logger.info(f"Cache miss for domain {domain}, fetching from VirusTotal")

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        headers = {
            "accept": CONTENT_TYPE,
            "x-apikey": VIRUSTOTAL_KEY
        }

        response = requests.get(url, headers=headers)
        response_json = response.json()
        try:
            data = response_json.get("data")
            domain_id = data.get("id")
            attributes = data.get("attributes")
            last_analysis = attributes.get("last_analysis_stats")
            malicious = last_analysis.get("malicious")
            suspicious = last_analysis.get("suspicious")
            undetected = last_analysis.get("undetected")
            harmless = last_analysis.get("harmless")
            total_count = malicious + suspicious + undetected + harmless
            if malicious == 0 and suspicious == 0:
                report = f"Domain {domain_id}: On VirusTotal no security vendors flagged this domain as malicious"
            elif malicious == 0 and suspicious >= 1:
                report = f"Domain {domain_id}: On VirusTotal {suspicious}/{total_count} security vendors flagged this domain as suspicious"
            else:
                report = f"Domain {domain_id}: On VirusTotal {malicious}/{total_count} security vendors flagged this domain as malicious"
            virustotal_cache.set(key, report, CACHE_TTL)
            return report
        except Exception as e:
            report = f"Error requesting the domain {domain}"
            logger.error(f"Error requesting the domain {domain}: {e}")
            return report
    else:
        logger.error(f"Domain {domain} is not valid")
        report = f"Domain {domain} is not valid"
        return report
    
def get_domain_report(domains):
    domains_info = []
    for domain in domains:
        domains_info.append(check_domain_in_virustotal(domain))
        
    return domains_info

def format_user_agent_string(response, user_agent_raw, key):
    if response.status_code == 200:
        try: 
            response_json = response.json()
            device = response_json.get('device')
            os = response_json.get('os')
            user_agent = response_json.get('userAgent')
            is_spider = response_json.get('isSpider')
            if is_spider == True:
                is_spider = "Yes"
            else:
                is_spider = "No"
            is_mobile = response_json.get("isMobile")
            if is_mobile == True:
                is_mobile = "Yes"
            else:
                is_mobile = "No"
            
            return_string = f"User agent: {user_agent} | Device: {device} | OS: {os} | Bot: {is_spider} | Mobile user agent: {is_mobile}"
            
            bigdata_cache.set(key, return_string, CACHE_TTL)
            return return_string
        except Exception as e:
            return_string = f"Error requesting user agent: {user_agent_raw}"
            logger.error(f"Error processing user agent {user_agent_raw}: {e}")
            return return_string
    else:
        return_string = f"Error requesting user agent: {user_agent_raw}"
        return return_string

def get_user_agent_info(user_agents_raw):
    url = "https://api-bdc.net/data/user-agent-info"
    user_agents_strings = []
    for user_agent_raw in user_agents_raw:
        key = f"bigdata:line:{user_agent_raw}"
        cached_line = bigdata_cache.get(key)
        if cached_line is not None:
            logger.info(f"Cache found for user_agent {user_agent_raw}")
            user_agents_strings.append(cached_line)
        else:
            logger.info(f"Cache miss for user_agent {user_agent_raw}, fetching from BigData")
        
            params = {
                'userAgentRaw': user_agent_raw,
                'key': BIG_DATA_USERAGENT_KEY
            }

            response = requests.get(url, params=params)
            
            user_agent_string = format_user_agent_string(response, user_agent_raw, key)
            user_agents_strings.append(user_agent_string)

    return user_agents_strings

def scan_url_virustotal(urls_to_scan):
    urls_info = []
    for url_to_scan in urls_to_scan:
        key = f"virustotal:line:{url_to_scan}"
        cached_line = virustotal_cache.get(key)
        if cached_line is not None:
            logger.info(f"Cache found for URL {url_to_scan}")
            urls_info.append(cached_line)
        else:
            logger.info(f"Cache miss for URL {url_to_scan}, fetching from VirusTotal")

        
            url = "https://www.virustotal.com/api/v3/urls"

            payload = { "url": url_to_scan }
            headers = {
                "accept": CONTENT_TYPE,
                "x-apikey": VIRUSTOTAL_KEY,
                "content-type": "application/x-www-form-urlencoded"
            }

            response = requests.post(url, data=payload, headers=headers)
            response_json = response.json()
            data = response_json.get("data")
            scan_id = data.get('id')
            # Give time for the scan to complete
            time.sleep(15)  # Wait for 15 seconds before checking the scan result
            report = get_url_analisis(url_to_scan, scan_id)
            virustotal_cache.set(key, report, CACHE_TTL)
            urls_info.append(report)

    return urls_info

def get_url_analisis(url_to_scan, scan_id):

    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

    headers = {
        "accept": CONTENT_TYPE,
        "x-apikey": VIRUSTOTAL_KEY
    }

    response = requests.get(url, headers=headers)
    try:
        response_json = response.json()
        data = response_json.get("data")

        attributes = data.get("attributes")
        stats = attributes.get("stats")
        malicious = stats.get("malicious")
        suspicious = stats.get("suspicious")
        undetected = stats.get("undetected")
        harmless = stats.get("harmless")
        total_count = malicious + suspicious + undetected + harmless

        if malicious == 0 and suspicious == 0:
            report = f"URL {url_to_scan}: On VirusTotal no security vendors flagged this URL as malicious"
        elif malicious == 0 and suspicious >= 1:
            report = f"URL {url_to_scan}: On VirusTotal {suspicious}/{total_count} security vendors flagged URL domain as suspicious"
        else:
            report = f"URL {url_to_scan}: On VirusTotal {malicious}/{total_count} security vendors flagged URL domain as malicious"
    except Exception as e:
        report = f"Error requesting the URL {url_to_scan}"
        logger.error(f"Error requesting the URL {url_to_scan}: {e}")

    return report

def get_hash_reports(hash):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"

    headers = {
        "accept": CONTENT_TYPE,
        "x-apikey": VIRUSTOTAL_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        # Check if the response is 404 Not Found
        if response.status_code == 404:
            logger.error(f"Hash {hash} not found on VirusTotal")
            report = f"Hash {hash} not found on VirusTotal"
            return report
        
        response_json = response.json()
        data = response_json.get("data")
        attributes = data.get("attributes")
        signature_info = attributes.get("signature_info")
        try:
            original_name = signature_info.get("original name")
        except Exception as e:
            original_name = "Not found"
            logger.error(f"Error getting original name for hash {hash}: {e}")
        last_analysis_stats = attributes.get("last_analysis_stats")
        malicious = last_analysis_stats.get("malicious")
        suspicious = last_analysis_stats.get("suspicious")
        undetected = last_analysis_stats.get("undetected")
        total_count = malicious + suspicious + undetected

        if malicious == 0 and suspicious == 0:
            report = f"Original name: {original_name}: On VirusTotal no security vendors flagged this HASH as malicious"
        elif malicious == 0 and suspicious >= 1:
            report = f"Original name: {original_name}: On VirusTotal {suspicious}/{total_count} security vendors flagged this HASH as suspicious"
        else:
            report = f"Original name: {original_name}: On VirusTotal {malicious}/{total_count} security vendors flagged this HASH as malicious"
    except Exception as e:
        logger.error(f"Error requesting the HASH {hash}: {e}")
        report = f"Error requesting the HASH {hash}"

    return report


def extract_hashes(data):
    # Define the regex patterns for MD5, SHA-1, and SHA-256 hashes
    md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
    sha1_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
    sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')

    # Split the input by lines and strip any surrounding whitespace
    hashes = [line.strip() for line in data.splitlines() if line.strip()]

    # Validate each hash
    valid_hashes = []
    for h in hashes:
        if md5_pattern.match(h):
            valid_hashes.append(h)
        elif sha1_pattern.match(h):
            valid_hashes.append(h)
        elif sha256_pattern.match(h):
            valid_hashes.append(h)
        else:
            valid_hashes.append(f"Hash: {h} not valid")

    return valid_hashes

def scan_hashes_logic(data):
    valid_hashes = extract_hashes(data)
    reports = []
    for hash in valid_hashes:
        key = f"virustotal:line:{hash}"
        cached_line = virustotal_cache.get(key)
        if cached_line is not None:
            logger.info(f"Cache found for Hash {hash}")
            reports.append(cached_line)
        else:
            logger.info(f"Cache miss for Hash {hash}, fetching from VirusTotal")

            if "not valid" in hash:
                reports.append(hash)
            else:
                report = get_hash_reports(hash)
                virustotal_cache.set(key, report, CACHE_TTL)
                reports.append(report)
    return reports


# Here we start logging events to the database

# This function logs IP events to the database
def log_ip_events(ips, user, source):
    rows = []
    for raw in ips:
        try:
            value, ver = normalize_ip(raw)
            rows.append(IpLookup(value=value, raw_value=raw, ip_version=ver, user=user, source=source))
        except Exception as e:
            logger.error(f"Error normalizing IP {raw}: {e}")
            continue
    if rows:
        IpLookup.objects.bulk_create(rows, ignore_conflicts=False)

# This function logs Domain events to the database
def log_domain_events(domains, user, source):
    rows = []
    for raw in domains:
        value = normalize_domain(raw)
        rows.append(DomainLookup(value=value, raw_value=raw, user=user, source=source))
    if rows:
        DomainLookup.objects.bulk_create(rows)

# This function logs URL events to the database
def log_url_events(urls, user, source):
    rows = []
    for raw in urls:
        value = normalize_url(raw)
        rows.append(UrlLookup(value=value, raw_value=raw, user=user, source=source))
    if rows:
        UrlLookup.objects.bulk_create(rows)

# This function logs User-Agent events to the database
def log_ua_events(uas, user, source):
    rows = []
    for raw in uas:
        value = normalize_user_agent(raw)
        rows.append(UserAgentLookup(value=value, raw_value=raw, user=user, source=source))
    if rows:
        UserAgentLookup.objects.bulk_create(rows)

def log_hash_events(hashes, user, source):
    rows = []
    for raw in hashes:
        value = normalize_user_agent(raw)
        rows.append(HashLookup(value=value, raw_value=raw, user=user, source=source))
    if rows:
        HashLookup.objects.bulk_create(rows)


def check_db(alias="default"):
    start = time.perf_counter()
    try:
        conn = connections[alias]
        # Make sure a stale/dead connection is recycled if needed.
        conn.close_if_unusable_or_obsolete()
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            cur.fetchone()
        return {"ok": True, "latency_ms": round((time.perf_counter() - start) * 1000, 2)}
    except Exception as e:
        return {"ok": False, "error": str(e), "latency_ms": round((time.perf_counter() - start) * 1000, 2)}


def check_cache(alias="default"):
    start = time.perf_counter()
    try:
        cache = caches[alias]
        # If using django-redis, prefer a lightweight PING.
        client = getattr(cache, "client", None)
        if client is not None:
            # Works for django-redis (get_client returns a Redis client with .ping()).
            redis_client = client.get_client(write=True)
            if hasattr(redis_client, "ping"):
                redis_client.ping()
            else:
                # Fallback to set/get/delete if client has no ping()
                key = f"healthz:{uuid4()}"
                cache.set(key, "1", timeout=5)
                _ = cache.get(key)
                cache.delete(key)
        else:
            # Generic cache backend fallback: set/get/delete
            key = f"healthz:{uuid4()}"
            cache.set(key, "1", timeout=5)
            _ = cache.get(key)
            cache.delete(key)

        return {"ok": True, "latency_ms": round((time.perf_counter() - start) * 1000, 2)}
    except Exception as e:
        return {"ok": False, "error": str(e), "latency_ms": round((time.perf_counter() - start) * 1000, 2)}