![IMAGE](authninja-demo/authninja-logo.png)

**AuthNinja** is a tool designed to quickly check outbound email authentication settings such as **SPF, DKIM, DMARC, MTA-STS and SMTP DANE** directly from the terminal.

## Required Python packages
- `requests`: `python3 -m pip install requests`
- `pyfiglet` and `colorama`: `python3 -m pip install pyfiglet colorama`
- `dnspython`: `python3 -m pip install dnspython`

## Start AuthNinja
1. Place `authninja.py` in a local folder, such as your [Python virtual environment](https://github.com/vand3rlinden/Python?tab=readme-ov-file#installation-of-python): `~/py_envs/scripts`.
2. Enable your virtual Python environment: `source ~/py_envs/bin/activate`
3. Browse to the path: `cd py_envs/scripts`
4. Start AuthNinja: `python3 authninja.py`

## AuthNinja demo
### Menu:
![IMAGE](authninja-demo/authninja-menu.png)

### Query results:
![IMAGE](authninja-demo/authninja-query.png)

