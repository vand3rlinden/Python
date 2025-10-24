# Overview
This repository contains Python projects that can be used to perform certain tasks.

## Current Python projects
- [ThreatHunterX](https://github.com/vand3rlinden/Python/tree/main/ThreatHunterX)
  - ThreatHunterX is a tool designed to assist SOC Analysts. The primary goal of ThreatHunterX is to perform routine checks and free up time for more in-depth analysis.
- [AuthNinja](https://github.com/vand3rlinden/Python/tree/main/AuthNinja)
  - AuthNinja is a tool designed to quickly check outbound email authentication settings such as SPF, DKIM, and DMARC directly from the terminal. Verify your email security effortlessly with just a few commands.
- [SubnetBuddy](https://github.com/vand3rlinden/Python/tree/main/SubnetBuddy)
  - SubnetBuddy is a tool that simplifies and streamlines the process of calculating subnets. Whether you're a network engineer, system administrator, or working in cybersecurity, SubnetBuddy provides an intuitive interface for calculating subnets, subnet masks, and IP ranges with ease.
- [MDO SafeLinks Decoder](https://github.com/vand3rlinden/Python/tree/main/MDOSafeLinksDecoder)
  - MDO SafeLinks Decoder is created to decode SafeLinks URLs locally without using any online third-party tools. Since most SafeLinks URLs contain the user’s UPN, it is not confidential to decode them through online third-party tools.

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
