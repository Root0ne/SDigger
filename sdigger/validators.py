import re
import ipaddress
from typing import List, Tuple

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}$'
    )
    return True if domain_regex.match(domain) else False

def validate_dns_servers(dns_servers: List[str]) -> Tuple[List[str], List[str]]:
    valid_dns_servers = []
    invalid_dns_servers = []
    for ip in dns_servers:
        ip = ip.strip()
        if validate_ip(ip):
            valid_dns_servers.append(ip)
        else:
            invalid_dns_servers.append(ip)
    return valid_dns_servers, invalid_dns_servers
