# SDigger

![SDigger UI](./image.png)

**SDigger** is a comprehensive and efficient subdomain discovery and analysis tool designed for security researchers, red teamers, and threat intelligence analysts. It helps you identify subdomains for a given domain, perform DNS resolution, retrieve HTTP headers, fetch SSL/TLS certificate information, and conduct in-depth SSL/TLS analysis. SDigger offers powerful features like proxy support, custom headers, cookies, and the ability to export results in CSV and JSON formats.

Note: I recommend using [SecList](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS) for subdomain wordlist.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
- [Usage and Examples](#usage-and-examples)
  - [Basic Subdomain Discovery](#basic-subdomain-discovery)
  - [Using Custom Headers and Cookies](#using-custom-headers-and-cookies)
  - [Advanced Configuration](#advanced-configuration)
  - [Using Proxy Servers with CSV File](#using-proxy-servers-with-csv-file)
- [Output Formats](#output-formats)
  - [Downloading Results in JSON Format](#downloading-results-in-json-format)
  - [Downloading Results in CSV Format](#downloading-results-in-csv-format)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Subdomain Discovery**: Scans for subdomains using a custom wordlist.
- **DNS Resolution**: Resolves subdomains to IP addresses using specified DNS servers.
- **HTTP Header Retrieval**: Fetches HTTP headers, status codes, and HTML titles from discovered subdomains.
- **SSL Certificate Analysis**: Retrieves SSL certificate details, including validity, issuer, and expiration date.
- **In-depth SSL/TLS Analysis**: Analyzes supported SSL/TLS protocols and ciphers.
- **Concurrency**: High-performance asynchronous requests with customizable concurrency limits.
- **Custom Headers and Cookies**: Add custom HTTP headers and cookies to requests.
- **Proxy Support**: Route requests through a proxy by providing a single proxy or uploading a CSV file with proxy details.
- **Progress Tracking**: Real-time progress updates during subdomain discovery.
- **Export Results**: Download results in both CSV and JSON formats for further analysis.

## Installation

### Prerequisites

- Python 3.7 or higher
- `pip` package manager

### Setup

1. **Clone the Repository**

```bash
git clone https://github.com/Root0ne/SDigger.git
cd SDigger
```

2. **Install Dependencies**

```bash
pip install -r requirements.txt
```

3. **Run the Application**

```bash
streamlit run SDigger.py
```

   The application will open in your default web browser at `http://localhost:8501`.

## Usage and Examples

### Basic Subdomain Discovery

To perform a basic subdomain discovery:

1. **Domain**: Enter the domain, for example, `example.com`.
2. **Wordlist File**: Upload a text file (`subdomains.txt`) with the following content:

   ```
   www
   mail
   ftp
   api
   admin
   ```

3. **Start Discovery**: Click the **Start Discovery** button to begin the scan. SDigger will attempt to resolve each subdomain and fetch associated details like IP addresses, HTTP headers, and SSL certificate information.

### Using Custom Headers and Cookies

You can add custom HTTP headers and cookies to the requests, which is useful for bypassing protections or adding authentication.

1. **Additional Headers** section:
   
   Enter headers in the format `Key: Value`, one per line.
   
   ```
   User-Agent: CustomUserAgent/1.0
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   Accept-Language: en-US,en;q=0.9,fr;q=0.8
   Cache-Control: no-cache
   X-Forwarded-For: 123.45.67.89
   Referer: https://www.google.com/
   Origin: https://example-origin.com
   ```

2. **Cookies** section:
   
   Enter cookies in `Key=Value` format, one per line.
   
   ```
   sessionid=abc123def456ghi789jkl012
   userid=1001
   auth_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
   preferences=theme=dark&layout=grid
   cart=product1:2;product2:5
   tracking_id=UA-12345678-1
   ```

3. **Start Discovery**: After entering your custom headers and cookies, click **Start Discovery** to apply them to all HTTP requests.

### Advanced Configuration

For more granular control over the discovery process, you can configure advanced settings such as DNS servers, concurrent requests, and timeouts:

- **DNS Servers**: DNS Servers: You can provide faster DNS resolution by using different DNS servers.
  
  Example:
  
  ```
  8.8.8.8, 1.1.1.1
  ```

- **Max Concurrent Requests**: The number of simultaneous scans can be set.
- **Enable SSL/TLS Deep Analysis**: It can analyze the SSL/TLS of the subdomains you find at a basic level.
- **HTTP Timeout**: The timeout period can be set to avoid waiting too long for unresponsive or slow subdomains.

### Using Proxy Servers with CSV File

SDigger supports using proxies to route requests through multiple proxy servers. This feature is useful for anonymizing requests or working around IP-based rate limits.

#### CSV File Format

When using multiple proxies, upload a CSV file containing the following columns:

- **Required Columns**: `protocol`, `ip`, `port`
- **Optional Columns**: `username`, `password`

**Example CSV**:

```csv
protocol,ip,port,username,password
http,proxy1.example.com,8080,,
https,proxy2.example.com,8443,user1,pass1
http,192.168.1.100,3128,,
```

#### Steps

1. **Use Proxy**: Select **Proxy List** from the dropdown.
2. **Upload Proxy List CSV File**: Upload your CSV file containing proxy details.
3. **Start Discovery**: Click **Start Discovery** to begin routing requests through the specified proxy servers.

---

## Output Formats

SDigger allows exporting the discovery results in both **JSON** and **CSV** formats for further processing and analysis.

### Downloading Results in JSON Format

Once the discovery process is complete, click the **Download Results as JSON** button. A JSON file will be downloaded containing the data for the discovered subdomains.

**Sample JSON Output**:

```json
[
  {
    "subdomain": "www.example.com",
    "ip_addresses": ["93.184.216.34"],
    "org_info": "Example Organization",
    "http_status": 200,
    "html_title": "Example Domain",
    "http_headers": "Headers information...",
    "ssl_certificate": "SSL certificate details..."
  },
  {
    "subdomain": "mail.example.com",
    "ip_addresses": ["93.184.216.35"],
    "org_info": "Example Organization",
    "http_status": 404,
    "html_title": null,
    "http_headers": "Headers information...",
    "ssl_certificate": null
  }
]
```

### Downloading Results in CSV Format

You can also **download the results in CSV** format by clicking on the Download button at the top right of the table. The CSV file will contain columns like Subdomain, IP Addresses, Status Code, HTML Title, HTTP Headers, and SSL Certificate.

**Sample CSV Output**:

```csv
Subdomain,IP Addresses,Status Code,HTML Title,HTTP Headers,SSL Certificate
www.example.com,"93.184.216.34",200,"Example Domain","Header information...","SSL certificate details..."
mail.example.com,"93.184.216.35",404,,,"Header information..."
```

---

## Contributing

We welcome and encourage contributions from the community! Whether you want to suggest a new feature, report a bug, or contribute improvements to the code, we would love to hear from you.

Feel free to share your thoughts, ideas, and improvements. Your contributions help make SDigger better for everyone!

For bug reports and feature requests, please don't hesitate to open an issue on GitHub. Providing detailed information will help us address the issue or feature request more effectively.

---

## License

SDigger is licensed under the MIT License.

---

**Disclaimer**: This tool is intended for educational and authorized security testing purposes only. Unauthorized use of this tool against systems without explicit permission is illegal and unethical.
