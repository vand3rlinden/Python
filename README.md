# Overview
This repository contains Python projects that can serve as a Swiss Army knife for your day-to-day work in cybersecurity.

## Current Python projects
- [AuthNinja](https://github.com/vand3rlinden/Python/tree/main/AuthNinja)
  - AuthNinja is a tool designed to quickly check outbound and inbound email authentication to get settings such as SPF, DKIM, DMARC, MTA-STST and SMTP DANE directly from the terminal.
- [SubnetBuddy](https://github.com/vand3rlinden/Python/tree/main/SubnetBuddy)
  - SubnetBuddy is a tool that calculating subnets.
- [MDO SafeLinks Decoder](https://github.com/vand3rlinden/Python/tree/main/MDOSafeLinksDecoder)
  - MDO SafeLinks Decoder is created to decode SafeLinks URLs locally without using any online third-party tools. Since most SafeLinks URLs contain the user’s UPN, it is not confidential to decode them through online third-party tools.
- [Base64Decoder](https://github.com/vand3rlinden/Python/tree/main/Base64Decoder)
  - Toolkit for decode from Base64 and encode to Base64
- [HTTPHeaderAnalyzer](https://github.com/vand3rlinden/Python/tree/main/HTTPHeaderAnalyzer)
  - A tool that fetches and analyses Security HTTP response headers, flagging misconfigurations and missing headers with actionable remediation tips
- [md2pdf](https://github.com/vand3rlinden/Python/tree/main/md2pdf)
  - Convert Markdown files to PDF with syntax-highlighted code blocks and styled tables

## Installation of Python
1. Depending on your host operating system, you can download the latest version of Python from its [official website](https://www.python.org/downloads/) or install it using your package manager.
   - MacOS (Homebrew): `brew install python@3.13`
   - Debian based distro (APT): `apt-get install python3`
2. Verify the installation: `python3 --version`

## Installing Python Packages using pip in a Virtual Environment
To avoid the risks associated with installing packages directly on your system, you can run Python in a virtual environment. This is a recommended approach because it keeps your system clean and avoids potential conflicts.

1. Create a Virtual Environment folder in your root path: `python3 -m venv ~/py_envs`
2. Activate the Virtual Environment: `source ~/py_envs/bin/activate`
3. Install Python packages such as `requests` in the Virtual Environment: `python3 -m pip install requests`
