import json
import streamlit as st
from typing import Optional
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

def get_organization(ip: str) -> Optional[str]:
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(asn_methods=['whois'])
        org_name = results.get('network', {}).get('name', '').strip()
        if org_name:
            return org_name
        else:
            return None
    except IPDefinedError:
        return None
    except Exception:
        return None

def create_download_data():
    if "table_data" in st.session_state:
        return json.dumps(
            st.session_state.table_data, indent=4
        ).encode("utf-8")
    return b""
