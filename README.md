# Overview
This repository contains Python scripts that can be used to perform certain tasks.

## Current Python scripts
- [ThreatHunter]()
  - ThreatHunter is a tool designed to assist SOC analysts by automating aspects of their workflow. One of ThreatHunter’s primary objectives is to handle routine checks, freeing up analysts’ time for more in-depth analysis within the same time frame.

## Installation of Python
1. Depending on your host operating system, you can download the latest version of Python from its [official website](https://www.python.org/downloads/) or install it using your package manager.
   - MacOS (Homebrew): `brew install python@3.12`
   - Debian based distro (APT): `apt-get install python3`
2. Verify the installation: `python3 --version`

## Install Python packages using pip by using a Virtual Environment
To avoid the risks associated with installing packages directly into the system Python environment, you can use a virtual environment. This is a recommended approach as it keeps your system Python environment clean and avoids potential conflicts.

1. Create a Virtual Environment folder in your root path: `python3 -m venv ~/py_envs`
2. Activate the Virtual Environment: `source ~/py_envs/bin/activate`
3. Install Python packages such as `requests` in the Virtual Environment: `python3 -m pip install requests`
