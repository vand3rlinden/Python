import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Replace with your SendGrid API Key
SENDGRID_API_KEY = 'SENDGRID_API_KEY'

# Email details
from_email = '"Shaggy Rogers" <shaggy@domain.com>'
to_email = 'recipient@domain.com'
subject = 'Test Email'
content = 'Hi,\n\nThis is a test email.\n\nBest regards,\nShaggy'

# Create the Mail object
message = Mail(
    from_email=from_email,
    to_emails=to_email,
    subject=subject,
    plain_text_content=content
)

try:
    sg = SendGridAPIClient(SENDGRID_API_KEY)
    response = sg.send(message)
    if 200 <= response.status_code < 300:
        print('✅ Email sent successfully!')
    else:
        print(f'⚠️ Failed to send email. Status code: {response.status_code}')
        print(f'Body: {response.body}')
except Exception as e:
    print('❌ An error occurred while sending the email:')
    print(e)