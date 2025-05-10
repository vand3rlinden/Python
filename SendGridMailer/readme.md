**SendGridMailer** is a tool used to send and test outbound emails via the SendGrid API.

## API Key for SendGrid
You can register at [SendGrid](https://app.sendgrid.com) to obtain a free API key, which allows you to send up to 100 emails per day.

## Required Python packages
- `sendgrid`: `python3 -m pip install sendgrid`

## Start 
1. Place `send_mail.py` in a local folder, such as your Python virtual environment: `~/py_envs/scripts`.
2. Enable your virtual Python environment: `source ~/py_envs/bin/activate`.
3. Browse to the path: `cd py_envs/scripts`.
4. Edit `send_mail.py`: `nano send_mail.py`, and insert your API key and configure the email details (such as sender, recipient, subject, and body).
5. Run SendGridMailer: `python3 send_mail.py`.