import asyncio
import logging
import pandas as pd
import streamlit as st

from modules.constants import DEFAULT_DNS_SERVERS
from modules.validators import validate_domain, validate_dns_servers
from modules.subdomain_discovery import SubdomainDiscovery
from modules.helpers import create_download_data
from modules.async_functions import run_discovery

def main():
    st.set_page_config(page_title="SDigger", layout="wide")

    hide_streamlit_style = """
        <style>
        /* Hide Streamlit default menu and footer */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}

        /* Adjust padding */
        .block-container {
            padding-top: 0rem;
            padding-bottom: 1rem;
            padding-left: 2rem;
            padding-right: 2rem;
        }

        /* Reduce margin for title */
        .custom-title {
            margin-bottom: 0.5rem;
        }

        /* Reduce space above buttons */
        .button-container {
            margin-top: 0.5rem;
        }

        /* General page layout */
        body {
            margin: 0;
            padding: 0;
        }
        </style>
    """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True)

    st.markdown("""
    <link href="https://fonts.googleapis.com/css2?family=VT323&display=swap" rel="stylesheet">
    <div class="custom-title" style="font-family: 'VT323', monospace; font-size:60px; color: #00FF00; margin-bottom: 0.5rem;">
        SDigger
    </div>
    <hr style="margin-top: 0.5rem; margin-bottom: 1rem;">
    """, unsafe_allow_html=True)

    st.markdown(
         f"""
         <div style="position: fixed; bottom: 10px; right: 10px; font-size: 12px; color: #777;">
             Developed by <a href="https://x.com/Root0ne" target="_blank">@Root0ne</a>
         </div>
         """,
         unsafe_allow_html=True
    )

    with st.sidebar:
        domain = st.text_input("Domain:")
        wordlist_file = st.file_uploader("Wordlist File:", type=["txt"])
        dns_servers_input = st.text_input(
            "DNS Servers (comma separated):",
            value=", ".join(DEFAULT_DNS_SERVERS)
        )
        max_requests = st.number_input(
            "Max Concurrent Requests:",
            min_value=1, max_value=500, value=100,
            help="Choose a reasonable number to avoid overloading the system."
        )

        enable_dns_timeout = st.checkbox("Enable DNS Timeout", value=True)
        dns_timeout = st.number_input(
            "DNS Timeout (seconds):",
            min_value=1, value=3
        ) if enable_dns_timeout else None

        enable_http_timeout = st.checkbox("Enable HTTP Timeout", value=True)
        http_timeout = st.number_input(
            "HTTP Timeout (seconds):",
            min_value=1, value=30
        ) if enable_http_timeout else 30

        enable_ssl_tls_analysis = st.checkbox("Enable SSL/TLS Deep Analysis", value=True)
        st.session_state['enable_ssl_tls_analysis'] = enable_ssl_tls_analysis

        additional_headers_input = st.text_area(
            "Additional Headers (key:value per line):",
            help="Enter additional HTTP headers. One per line in 'Key: Value' format."
        )
        cookies_input = st.text_area(
            "Cookies (key=value per line):",
            help="Enter cookies. One per line in 'Key=Value' format."
        )

        proxy_option = st.selectbox(
            "Use Proxy:",
            options=["No Proxy", "Single Proxy", "Proxy List"],
            help="Proxy addresses should start with http:// or https:// and include the port number (e.g., http://127.0.0.1:8080). For proxies requiring authentication, specify in the proxy address: http://username:password@proxyserver:port."
        )

        if proxy_option == "Single Proxy":
            proxy_address = st.text_input(
                "Proxy Address (e.g., http://127.0.0.1:8080):"
            )
        elif proxy_option == "Proxy List":
            proxy_list_file = st.file_uploader(
                "Upload Proxy List CSV File:",
                type=["csv"],
                help="Upload a CSV file containing proxy information. Required columns: protocol, ip, port. Optional columns: username, password."
            )

    with st.container():
        col1, col2, col3 = st.columns([1, 1, 2], gap="small")

        with col1:
            start_button_pressed = st.button("Start Discovery")

        with col2:
            stop_button_pressed = st.button("Stop Discovery")

        with col3:
            st.download_button(
                label="Download Results as JSON",
                data=create_download_data(),
                file_name=f"{domain}_subdomains_headers.json"
                if domain else "subdomains_headers.json",
                mime="application/json"
            )

    progress_bar_placeholder = st.empty()
    progress_text_placeholder = st.empty()
    lines_tried_placeholder = st.empty()
    table_placeholder = st.empty()

    columns = ["Subdomain", "IP Addresses", "Status Code", "HTML Title", "HTTP Headers", "SSL Certificate"]

    if st.session_state.table_data:
        df = pd.DataFrame(st.session_state.table_data)
        df.index += 1

        display_df = df[[
            "subdomain", "ip_addresses_display", "http_status",
            "html_title", "http_headers", "ssl_certificate"
        ]]
    else:
        display_df = pd.DataFrame(columns=columns)

    display_df.rename(columns={
        "subdomain": "Subdomain",
        "ip_addresses_display": "IP Addresses",
        "http_status": "Status Code",
        "html_title": "HTML Title",
        "http_headers": "HTTP Headers",
        "ssl_certificate": "SSL Certificate"
    }, inplace=True)

    table_placeholder.dataframe(display_df, use_container_width=True)

    if st.session_state.is_discovery_running:
        progress_bar_placeholder.progress(
            st.session_state.get("progress", 0.0)
        )
        progress_text_placeholder.write(
            st.session_state.get("progress_text", "")
        )
        lines_tried_placeholder.empty()
    else:
        progress_bar_placeholder.empty()
        progress_text_placeholder.empty()
        if st.session_state.lines_tried > 0:
            lines_tried_placeholder.write(
                f"Total lines tried: {st.session_state.lines_tried}"
            )

    if st.session_state.errors:
        st.error("Errors occurred during discovery:")
        for error in st.session_state.errors:
            st.write(error)

    if start_button_pressed and not st.session_state.is_discovery_running:
        if not domain:
            st.error("Domain is required!")
        elif not validate_domain(domain.strip()):
            st.error("Invalid domain format!")
        elif wordlist_file is None:
            st.error("Wordlist file is required!")
        else:
            dns_servers = [ip.strip() for ip in dns_servers_input.split(',')] \
                if dns_servers_input else DEFAULT_DNS_SERVERS

            valid_dns_servers, invalid_dns_servers = validate_dns_servers(dns_servers)

            if invalid_dns_servers:
                st.error(f"The following DNS servers are invalid: {', '.join(invalid_dns_servers)}")
            elif not valid_dns_servers:
                st.error("No valid DNS servers configured.")
            else:
                try:
                    content = wordlist_file.read()
                    if content:
                        wordlist = content.decode('utf-8').splitlines()
                        if not wordlist:
                            raise ValueError("Wordlist file is empty.")
                    else:
                        raise ValueError("Wordlist file is empty or invalid.")

                    additional_headers = {}
                    if additional_headers_input:
                        for line in additional_headers_input.strip().split('\n'):
                            if ':' in line:
                                key, value = line.split(':', 1)
                                additional_headers[key.strip()] = value.strip()
                            else:
                                st.warning(f"Ignored invalid header line: {line}")

                    cookies = {}
                    if cookies_input:
                        for line in cookies_input.strip().split('\n'):
                            if '=' in line:
                                key, value = line.split('=', 1)
                                cookies[key.strip()] = value.strip()
                            else:
                                st.warning(f"Ignored invalid cookie line: {line}")

                    proxy_addresses = []
                    if proxy_option == "Single Proxy":
                        if proxy_address:
                            proxy_addresses.append(proxy_address.strip())
                    elif proxy_option == "Proxy List":
                        if proxy_list_file is not None:
                            import csv
                            try:
                                content = proxy_list_file.getvalue().decode('utf-8')
                                reader = csv.DictReader(content.splitlines())
                                required_fields = {'protocol', 'ip', 'port'}
                                if not required_fields.issubset(reader.fieldnames):
                                    st.error(f"CSV file must contain the following columns: {', '.join(required_fields)}")
                                else:
                                    for row in reader:
                                        protocol = row['protocol'].strip()
                                        ip = row['ip'].strip()
                                        port = row['port'].strip()
                                        username = row.get('username', '').strip()
                                        password = row.get('password', '').strip()

                                        if username and password:
                                            proxy = f"{protocol}://{username}:{password}@{ip}:{port}"
                                        else:
                                            proxy = f"{protocol}://{ip}:{port}"

                                        proxy_addresses.append(proxy)
                            except Exception as e:
                                st.error(f"Error reading proxy CSV file: {e}")
                        else:
                            st.error("Proxy list CSV file is required for Proxy List option.")

                    subdomain_discovery = SubdomainDiscovery(
                        domain=domain.strip(),
                        wordlist=wordlist,
                        dns_servers=valid_dns_servers,
                        max_concurrent_requests=max_requests,
                        dns_timeout=dns_timeout,
                        http_timeout=http_timeout,
                        additional_headers=additional_headers,
                        cookies=cookies,
                        proxy_addresses=proxy_addresses 
                    )

                    st.session_state.subdomain_discovery = subdomain_discovery
                    st.session_state.table_data = []
                    st.session_state.errors = []
                    st.session_state.progress = 0.0
                    st.session_state.progress_text = ""
                    st.session_state.is_discovery_running = True
                    st.session_state.lines_tried = 0

                    lines_tried_placeholder.empty()

                    update_queue = asyncio.Queue()

                    async def main_loop():
                        discovery_task = asyncio.create_task(
                            run_discovery(
                                st.session_state.subdomain_discovery,
                                update_queue
                            )
                        )
                        while True:
                            update = await update_queue.get()
                            if update["type"] == "progress":
                                st.session_state.progress = update["progress"]
                                st.session_state.progress_text = update["text"]
                                st.session_state.lines_tried = update.get("lines_tried", 0)
                                progress_bar_placeholder.progress(
                                    st.session_state.progress
                                )
                                progress_text_placeholder.write(
                                    st.session_state.progress_text
                                )
                            elif update["type"] == "subdomain":
                                full_subdomain = f"{update['subdomain']}." \
                                                 f"{st.session_state.subdomain_discovery.domain}"
                                row = next(
                                    (
                                        row for row in
                                        st.session_state.table_data
                                        if row["subdomain"] == full_subdomain
                                    ),
                                    None
                                )
                                if row is None:
                                    row = {
                                        "subdomain": full_subdomain,
                                        "ip_addresses": update["ip_addresses"],
                                        "org_info": update.get("org_info"),
                                        "http_status": None,
                                        "html_title": None,
                                        "http_headers": None,
                                        "ssl_certificate": None
                                    }
                                    st.session_state.table_data.append(row)

                                if update["result"]:
                                    if update["ssl_analysis"]:
                                        row["ssl_certificate"] = update["result"]
                                    else:
                                        row["http_headers"] = update["result"].get("headers")
                                        row["http_status"] = update["result"].get("status")
                                        row["html_title"] = update["result"].get("html_title")

                                ip_info = ', '.join(update["ip_addresses"])
                                if row.get("org_info"):
                                    ip_info += f" ({row['org_info']})"
                                row["ip_addresses_display"] = ip_info

                                df = pd.DataFrame(st.session_state.table_data)
                                df.index += 1
                                display_df = df[[
                                    "subdomain", "ip_addresses_display", "http_status",
                                    "html_title", "http_headers", "ssl_certificate"
                                ]]

                                display_df.rename(columns={
                                    "subdomain": "Subdomain",
                                    "ip_addresses_display": "IP Addresses",
                                    "http_status": "Status Code",
                                    "html_title": "HTML Title",
                                    "http_headers": "HTTP Headers",
                                    "ssl_certificate": "SSL Certificate"
                                }, inplace=True)

                                table_placeholder.dataframe(display_df, use_container_width=True)

                            elif update["type"] == "done":
                                break

                        await discovery_task
                        st.session_state.is_discovery_running = False
                        progress_bar_placeholder.empty()
                        progress_text_placeholder.empty()
                        lines_tried_placeholder.write(
                            f"Total lines tried: {st.session_state.lines_tried}"
                        )

                    asyncio.run(main_loop())

                except Exception as e:
                    st.error(
                        f"An error occurred: {e}"
                    )
                    st.session_state.is_discovery_running = False

    if stop_button_pressed and st.session_state.is_discovery_running:
        if st.session_state.subdomain_discovery:
            st.session_state.subdomain_discovery.stop()
            st.success("Discovery successfully stopped.")
        st.session_state.is_discovery_running = False
        progress_bar_placeholder.empty()
        progress_text_placeholder.empty()
        lines_tried_placeholder.write(
            f"Total lines tried: {st.session_state.lines_tried}"
        )

if __name__ == "__main__":
    if "is_discovery_running" not in st.session_state:
        st.session_state.is_discovery_running = False
        st.session_state.subdomain_discovery = None
        st.session_state.progress = 0.0
        st.session_state.progress_text = ""
        st.session_state.table_data = []
        st.session_state.errors = []
        st.session_state.lines_tried = 0

    main()
