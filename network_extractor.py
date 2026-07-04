import requests
import re
import time

# Your API keys - get these free
VT_API_KEY  = "YOUR_VIRUSTOTAL_API_KEY_HERE"
# MalwareBazaar needs no API key for basic queries


def check_ip_virustotal(ip):
    """Check an IP address on VirusTotal."""
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {'error': 'VT API key not set', 'ip': ip}

    try:
        headers  = {'x-apikey': VT_API_KEY}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers=headers, timeout=10
        )
        if response.status_code == 200:
            data       = response.json()
            stats      = data['data']['attributes']['last_analysis_stats']
            malicious  = stats.get('malicious', 0)
            total      = sum(stats.values())
            return {
                'ip'       : ip,
                'malicious': malicious,
                'total'    : total,
                'verdict'  : 'MALICIOUS' if malicious > 3 else
                             'SUSPICIOUS' if malicious > 0 else 'CLEAN'
            }
    except Exception as e:
        return {'error': str(e), 'ip': ip}

    return {'ip': ip, 'verdict': 'UNKNOWN'}


def check_hash_malwarebazaar(file_hash):
    """
    Check a file hash on MalwareBazaar.
    MalwareBazaar is a free database of malware samples.
    No API key needed!
    """
    try:
        response = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': file_hash},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('query_status') == 'ok':
                info = data['data'][0]
                return {
                    'found'        : True,
                    'file_name'    : info.get('file_name', 'Unknown'),
                    'file_type'    : info.get('file_type', 'Unknown'),
                    'signature'    : info.get('signature', 'Unknown'),
                    'tags'         : info.get('tags', []),
                    'first_seen'   : info.get('first_seen', 'Unknown'),
                    'verdict'      : 'MALICIOUS',
                    'is_malicious' : True,
                    'source'       : 'MalwareBazaar'
                }
            else:
                return {
                    'found'        : False,
                    'verdict'      : 'NOT FOUND',
                    'is_malicious' : False,
                    'note'         : 'Not in MalwareBazaar database',
                    'source'       : 'MalwareBazaar'
                }
    except Exception as e:
        return {'error': str(e), 'found': False}

    return {'found': False, 'verdict': 'UNKNOWN'}


def check_multiple_iocs(iocs_dict):
    """
    Takes the IOCs extracted by static_analyzer.py and
    checks each one. Returns enriched results.

    iocs_dict looks like:
    {
        'ips'  : ['1.2.3.4', '5.6.7.8'],
        'urls' : ['http://evil.com'],
        ...
    }
    """
    results = {
        'ip_results'  : [],
        'url_results' : [],
        'summary'     : {
            'total_checked' : 0,
            'malicious'     : 0,
            'suspicious'    : 0,
            'clean'         : 0
        }
    }

    # Check IPs (limit to 3 to stay within free API limits)
    for ip in iocs_dict.get('ips', [])[:3]:
        # Skip private/local IPs
        if (ip.startswith('192.168') or ip.startswith('10.') or
                ip.startswith('127.') or ip.startswith('172.')):
            continue

        ip_result = check_ip_virustotal(ip)
        results['ip_results'].append(ip_result)
        results['summary']['total_checked'] += 1

        verdict = ip_result.get('verdict', 'UNKNOWN')
        if verdict == 'MALICIOUS':
            results['summary']['malicious'] += 1
        elif verdict == 'SUSPICIOUS':
            results['summary']['suspicious'] += 1
        else:
            results['summary']['clean'] += 1

        time.sleep(0.5)  # Respect API rate limits

    return results


def extract_iocs_from_text(text):
    """
    Simple IOC extractor for plain text input.
    Used when user pastes text directly into the tool.
    """
    iocs = {
        'ips'     : [],
        'urls'    : [],
        'emails'  : [],
        'hashes'  : []
    }

    # IP addresses
    ips = re.findall(r'\b(\d{1,3}\.){3}\d{1,3}\b', text)
    iocs['ips'] = list(set(ips))[:10]

    # URLs
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
    iocs['urls'] = list(set(urls))[:10]

    # Emails
    emails = re.findall(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text
    )
    iocs['emails'] = list(set(emails))[:10]

    # File hashes (MD5=32, SHA1=40, SHA256=64 hex chars)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    iocs['hashes'] = list(set(hashes))[:5]

    return iocs