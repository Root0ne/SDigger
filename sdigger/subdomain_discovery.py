import asyncio
import logging
import re
import socket
import ssl
from datetime import datetime
from typing import List, Optional, Dict

import aiohttp
import dns.asyncresolver
import dns.exception
from OpenSSL import SSL
import streamlit as st

from .constants import DEFAULT_DNS_SERVERS
from .helpers import get_organization

class SubdomainDiscovery:

    def __init__(
        self,
        domain: str,
        wordlist: List[str],
        dns_servers: Optional[List[str]] = None,
        max_concurrent_requests: int = 100,
        dns_timeout: Optional[int] = None,
        http_timeout: int = 30,
        max_concurrent_analysis_tasks: int = 100,
        additional_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy_addresses: Optional[List[str]] = None,
    ):
        self.domain = domain
        self.wordlist = wordlist
        self.dns_servers = dns_servers if dns_servers else DEFAULT_DNS_SERVERS
        self.max_concurrent_requests = max_concurrent_requests
        self.dns_timeout = dns_timeout
        self.http_timeout = http_timeout
        self.errors = []
        self._stop_event = asyncio.Event()
        self.request_semaphore = asyncio.Semaphore(
            max_concurrent_requests
        )
        self.analysis_semaphore = asyncio.Semaphore(
            max_concurrent_analysis_tasks
        )
        self.additional_headers = additional_headers or {}
        self.cookies = cookies or {}
        self.proxy_addresses = proxy_addresses or [] 
        self.current_proxy_index = 0 

    def get_next_proxy(self) -> Optional[str]:
        if not self.proxy_addresses:
            return None
        proxy = self.proxy_addresses[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_addresses)
        return proxy

    async def fetch_http_headers(
        self,
        session: aiohttp.ClientSession,
        subdomain: str,
        ip_address: str
    ) -> Optional[Dict]:
        full_domain = f"{subdomain}.{self.domain}"

        for protocol in ['http', 'https']:
            url = f"{protocol}://{full_domain}"

            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; SubdomainDiscovery/1.0)"
            }
            headers.update(self.additional_headers)

            proxy = self.get_next_proxy() 

            try:
                async with self.analysis_semaphore:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=self.http_timeout,
                        cookies=self.cookies,
                        allow_redirects=True,
                        ssl=False,
                        proxy=proxy 
                    ) as response:
                        headers_text = ""
                        history = response.history if response.history else [response]
                        initial_status_code = history[0].status if history else response.status

                        for idx, resp in enumerate(response.history):
                            headers_text += f"Redirect {idx + 1} ({resp.status} {resp.url}):\n"
                            headers_text += "\n".join(
                                [f"{k}: {v}" for k, v in resp.headers.items()]
                            )
                            headers_text += "\n\n"
                        headers_text += f"Final Response ({response.status} {response.url}):\n"
                        headers_text += "\n".join(
                            [f"{k}: {v}" for k, v in response.headers.items()]
                        )

                        html_title = None

                        html_content = await response.text()
                        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
                        if title_match:
                            html_title = title_match.group(1).strip()

                        return {"headers": headers_text, "status": initial_status_code, "html_title": html_title}
            except aiohttp.ClientConnectorSSLError:
                continue
            except asyncio.TimeoutError:
                self.errors.append(f"HTTP Timeout: {full_domain}")
                break
            except aiohttp.ClientError as e:
                self.errors.append(
                    f"HTTP ClientError: {full_domain} - {str(e)}"
                )
                break
            except Exception as e:
                self.errors.append(
                    f"HTTP Error: {full_domain} - {str(e)}"
                )
                break
        return None

    def get_cert(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            context = SSL.Context(SSL.TLSv1_2_METHOD)
            sock.settimeout(5)
            sock.connect((host, int(port)))
            sock.settimeout(None)
            ssl_conn = SSL.Connection(context, sock)
            ssl_conn.set_tlsext_host_name(host.encode())
            ssl_conn.set_connect_state()
            ssl_conn.do_handshake()
            cert = ssl_conn.get_peer_certificate()
        finally:
            sock.close()

        return cert

    def get_cert_sans(self, x509cert):
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        return san.replace(',', ';')

    def get_cert_info(self, host, cert):
        context = {}
        cert_subject = cert.get_subject()
        cert_issuer = cert.get_issuer()

        context['host'] = host
        context['issued_to'] = getattr(cert_subject, 'CN', 'N/A')
        context['issued_o'] = getattr(cert_subject, 'O', 'N/A')
        context['issuer_o'] = getattr(cert_issuer, 'organizationName', 'N/A')
        context['issuer_c'] = getattr(cert_issuer, 'countryName', 'N/A')
        context['cert_sn'] = str(cert.get_serial_number())

        digest = cert.digest('sha256')
        if isinstance(digest, bytes):
            context['cert_sha256'] = digest.decode('utf-8')
        else:
            context['cert_sha256'] = digest

        sig_alg = cert.get_signature_algorithm()
        if isinstance(sig_alg, bytes):
            context['cert_alg'] = sig_alg.decode('utf-8', errors='ignore')
        else:
            context['cert_alg'] = sig_alg

        context['cert_ver'] = cert.get_version()
        context['cert_sans'] = self.get_cert_sans(cert)
        context['cert_valid'] = not cert.has_expired()

        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        context['valid_from'] = valid_from.strftime('%Y-%m-%d')

        valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        context['valid_till'] = valid_till.strftime('%Y-%m-%d')

        context['validity_days'] = (valid_till - valid_from).days
        context['days_left'] = (valid_till - datetime.now()).days
        context['expired'] = cert.has_expired()

        return context

    async def analyze_ssl_tls(
        self,
        subdomain: str,
        ip_address: str
    ) -> Optional[Dict]:
        """
        Perform deep SSL/TLS analysis to detect supported protocols and ciphers.

        Args:
            subdomain (str): The subdomain to analyze.
            ip_address (str): The IP address of the subdomain.

        Returns:
            Optional[Dict]: A dictionary containing SSL/TLS analysis results.
        """
        full_domain = f"{subdomain}.{self.domain}"
        protocols = {
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLS,
        }
        supported_protocols = []
        ciphers = set()

        for protocol_name, protocol in protocols.items():
            try:
                context = ssl.SSLContext(protocol)
                context.set_ciphers('ALL')
                with socket.create_connection((ip_address, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=full_domain) as ssock:
                        supported_protocols.append(protocol_name)
                        cipher_info = ssock.cipher()
                        if cipher_info:
                            ciphers.add(cipher_info[0])
            except ssl.SSLError as e:
                continue
            except Exception as e:
                self.errors.append(f"SSL/TLS Analysis Error: {full_domain} - {str(e)}")
                break

        if supported_protocols:
            weak_ciphers = [cipher for cipher in ciphers if 'RC4' in cipher or 'DES' in cipher or 'NULL' in cipher]
            analysis_result = {
                'supported_protocols': supported_protocols,
                'ciphers': list(ciphers),
                'weak_ciphers': weak_ciphers
            }
            ssl_tls_info_text = f"""
Supported Protocols: {', '.join(supported_protocols)}
Ciphers: {', '.join(ciphers)}
Weak Ciphers: {', '.join(weak_ciphers) if weak_ciphers else 'None'}
"""
            return {"ssl_tls_info": ssl_tls_info_text}
        else:
            return None

    async def fetch_ssl_certificate(
        self,
        subdomain: str,
        ip_address: str
    ) -> Optional[Dict]:
        """
        Fetch SSL certificate information and perform deep SSL/TLS analysis.
        """
        full_domain = f"{subdomain}.{self.domain}"

        try:
            async with self.analysis_semaphore:
                cert = await asyncio.to_thread(self.get_cert, ip_address, 443)
                cert_info = self.get_cert_info(full_domain, cert)

                ssl_info_text = f"""
Host: {cert_info['host']}
Issued to: {cert_info['issued_to']}
Organization: {cert_info['issued_o']}
Issuer: {cert_info['issuer_o']} ({cert_info['issuer_c']})
Valid from: {cert_info['valid_from']}
Valid till: {cert_info['valid_till']} ({cert_info['days_left']} days left)
Validity days: {cert_info['validity_days']}
Certificate valid: {cert_info['cert_valid']}
Certificate S/N: {cert_info['cert_sn']}
Certificate SHA256 FP: {cert_info['cert_sha256']}
Certificate version: {cert_info['cert_ver']}
Certificate algorithm: {cert_info['cert_alg']}
Expired: {cert_info['expired']}
Certificate SANs:
"""
                for san in cert_info['cert_sans'].split(';'):
                    ssl_info_text += f"  - {san.strip()}\n"

                if st.session_state.get('enable_ssl_tls_analysis', True):
                    ssl_tls_analysis = await self.analyze_ssl_tls(subdomain, ip_address)
                    if ssl_tls_analysis and ssl_tls_analysis.get("ssl_tls_info"):
                        cert_info["ssl_tls_analysis"] = ssl_tls_analysis["ssl_tls_info"]
                        ssl_info_text += "\nSSL/TLS Analysis:\n"
                        ssl_info_text += ssl_tls_analysis["ssl_tls_info"]

                return {"ssl_info": ssl_info_text}

        except Exception as e:
            self.errors.append(f"SSL Error: {full_domain} - {str(e)}")
            return None

    async def resolve_dns(self, subdomain: str, retries=3) -> Optional[List[str]]:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self.dns_servers
        if self.dns_timeout is not None:
            resolver.timeout = self.dns_timeout
            resolver.lifetime = self.dns_timeout

        full_domain = f"{subdomain}.{self.domain}"
        delay = 1
        for attempt in range(retries):
            try:
                async with self.request_semaphore:
                    answers = await resolver.resolve(full_domain, 'A')
                    return [str(answer) for answer in answers]
            except dns.exception.Timeout:
                self.errors.append(f"DNS Timeout: {full_domain}, retrying ({attempt+1}/{retries})")
            except dns.resolver.NXDOMAIN:
                self.errors.append(f"NXDOMAIN Error: {full_domain}")
                break
            except dns.resolver.NoNameservers:
                self.errors.append(f"DNS NoNameservers: {full_domain}, retrying ({attempt+1}/{retries})")
            except dns.exception.DNSException as e:
                self.errors.append(f"DNS Error: {full_domain} - {str(e)}, retrying ({attempt+1}/{retries})")
            except Exception as e:
                self.errors.append(f"Unexpected Error: {full_domain} - {str(e)}, retrying ({attempt+1}/{retries})")
            await asyncio.sleep(delay)
            delay *= 2

        return None

    async def run(
        self,
        log_callback,
        progress_callback,
        subdomain_callback
    ):
        total_lines = len(self.wordlist)
        line_count = 0

        connector = aiohttp.TCPConnector(ssl=False)
        tasks = []
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                for subdomain in self.wordlist:
                    if self._stop_event.is_set():
                        break
                    subdomain = subdomain.strip()
                    if not subdomain:
                        continue
                    line_count += 1
                    progress_callback(line_count, total_lines)

                    task = asyncio.create_task(
                        self.process_subdomain(
                            session,
                            subdomain,
                            log_callback,
                            subdomain_callback
                        )
                    )
                    tasks.append(task)

                    if len(tasks) >= self.max_concurrent_requests:
                        done, pending = await asyncio.wait(
                            tasks, return_when=asyncio.FIRST_COMPLETED
                        )
                        tasks = list(pending)

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

        except asyncio.CancelledError:
            log_callback("Discovery was cancelled.")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            log_callback(f"Error during execution: {str(e)}")
        finally:
            self._stop_event.clear()

    async def process_subdomain(
        self,
        session: aiohttp.ClientSession,
        subdomain: str,
        log_callback,
        subdomain_callback
    ):
        if self._stop_event.is_set():
            return

        try:
            dns_results = await self.resolve_dns(subdomain)
            if dns_results:
                ip_addresses = dns_results 
                org_names = set()
                for ip_address in ip_addresses:
                    org_name = get_organization(ip_address)
                    if org_name:
                        org_names.add(org_name)
                org_info = ', '.join(org_names) if org_names else None

                await subdomain_callback(subdomain, ip_addresses, org_info=org_info)

                first_ip = ip_addresses[0]

                analysis_tasks = []
                if not self._stop_event.is_set():
                    http_task = asyncio.create_task(
                        self.analyze_protocol(
                            session, subdomain, first_ip, "http", subdomain_callback
                        )
                    )
                    ssl_task = asyncio.create_task(
                        self.analyze_protocol(
                            session, subdomain, first_ip, "ssl", subdomain_callback
                        )
                    )
                    analysis_tasks.extend([http_task, ssl_task])

                if analysis_tasks:
                    await asyncio.gather(*analysis_tasks, return_exceptions=True)

        except Exception as e:
            log_callback(f"Error in process_subdomain ({subdomain}): {str(e)}")

    async def analyze_protocol(
        self,
        session: aiohttp.ClientSession,
        subdomain: str,
        ip_address: str,
        protocol: str,
        subdomain_callback
    ):
        try:
            if self._stop_event.is_set():
                return

            if protocol == "http":
                result = await self.fetch_http_headers(session, subdomain, ip_address)
                if result:
                    await subdomain_callback(subdomain, [ip_address], result)

            elif protocol == "ssl":
                result = await self.fetch_ssl_certificate(subdomain, ip_address)
                if result and result.get("ssl_info"):
                    await subdomain_callback(subdomain, [ip_address], result["ssl_info"], ssl_analysis=True)

        except Exception as e:
            self.errors.append(f"Analyze {protocol.upper()} error for subdomain {subdomain} (IP: {ip_address}): {str(e)}")

    def stop(self):
        self._stop_event.set()
        logging.info("Discovery stopping...")
