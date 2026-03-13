![IMAGE](threathunterx-demo/threathunterx-logo.png)

**ThreatHunterX** is a terminal tool designed to assist SOC Analysts. The primary goal of **ThreatHunterX** is to perform routine checks and free up time for more in-depth analysis.

## Requirements
1. API Key for VirusTotal 
2. API Key for AbuseIPDB
3. API Key for IPInfo
4. Python packages: 
   - `requests`: `python3 -m pip install requests`
   - `pyfiglet` and `colorama`: `python3 -m pip install pyfiglet colorama`

## API Key for VirusTotal 
You can register on [VirusTotal](https://www.virustotal.com/gui/join-us) to get a **free** API key with the following limits:
- Request rate: 4 lookups / min
- Daily quota: 500 lookups / day
- Monthly quota: 15.5 K lookups / month
- [API documentation](https://docs.virustotal.com/reference/overview)

## API Key for AbuseIPDB
You can register on [AbuseIPDB](https://www.abuseipdb.com/register?plan=free) to get a **free** API key with the following limits:
- Daily Limit: 1000 checks
- [API documentation](https://docs.abuseipdb.com)

## API Key for IPInfo
You can register on [IPInfo](https://ipinfo.io/pricing) to get a **free** API key with the following limits:
- Monthly Requests: Unlimited, but limited API Responses
- [API documentation](https://ipinfo.io/developers)

## Start ThreatHunterX
1. Place `threathunterx.py` in a local folder, such as your [Python virtual environment](https://github.com/vand3rlinden/Python?tab=readme-ov-file#installation-of-python): `~/py_envs/scripts`.
2. Enable your virtual Python environment: `source ~/py_envs/bin/activate`
3. Browse to the path: `cd py_envs/scripts`
4. Start ThreatHunterX: `python3 threathunterx.py`

## ThreatHunterX Menu
![IMAGE](threathunterx-demo/threathunterx-menu.png)