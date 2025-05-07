#!/usr/bin/env python3

import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import EmailMessage
from datetime import datetime

from_email = "andyprojects7@gmail.com"  
password = "ifho cyae dpin cwew"  # my google app password, will expire soon
body = 'Please find the attached log file.'

def send_email_to_admin(log_file_path, to_email):
    msg = EmailMessage()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = f"Log File For IAM Setup: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    msg.set_content(body)
    with open(log_file_path, 'rb') as f:
        file_data = f.read()
        file_name = f.name
    msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=file_name)

    
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()  # Start TLS encryption
            server.login(from_email, password)
            server.sendmail(from_email, to_email, msg.as_string())
    except Exception as e:
        print(f"Failed to send email to {to_email}: {str(e)}")


def send_email(to_email, name, username, user_password):
    
    subject = f"{username} User Account Created"
    body_text = f"Hello {to_email},\n\nYour account has been created. Please change your password upon first login.\n\nRegards,\nIAM Admin"

    # Set up the MIME
    msg = MIMEMultipart('alternative')
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    # Plain-text fallback (optional)
    if body_text:
        msg.attach(MIMEText(body_text, 'plain'))

    # Bootstrap-styled HTML email template
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Template</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
            }}
            .email-container {{
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }}
            .header {{
                background-color: #0d6efd;
                color: white;
                padding: 20px;
                text-align: center;
                border-radius: 5px 5px 0 0;
            }}
            .content {{
                padding: 20px;
                background-color: #f8f9fa;
                border-radius: 0 0 5px 5px;
            }}
            .footer {{
                margin-top: 20px;
                text-align: center;
                font-size: 12px;
                color: #6c757d;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <h1>Hello {name}!</h1>
            </div>
            <div class="content">
                <p>This is a confirmation of your workspace Creation</p>
                 <small>"You must change your temporary password. Complexity requirements:"</small></p>
                 <small>"- Minimum 12 characters"</small>
                 <small>"- At least one lowercase letter"</small>
                 <small>"- At least one uppercase letter"</small>
                 <small>"- At least one digit"</small>
                <small>"- At least one special character (!@#$%^&*)"</small>

                <p>Here are your account details:</p>
                <p>username: <strong>{username}</strong></p>
                <p>password: <strong>{user_password}</strong></p>
            
                <p class="mt-3">Contact SysAdmin? <a href="www.linkedin.com/in/andy-amponsah-bb72671b5">Contact Admin</a></p>
            </div>
            <div class="footer">
                <p>© 2025. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """

    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()  # Start TLS encryption
            server.login(from_email, password)
            server.sendmail(from_email, to_email, msg.as_string())
            print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email to {to_email}: {str(e)}")

if __name__ == "__main__":
    try:
        if sys.argv[1] == '--Admin-alert':
            send_email_to_admin(sys.argv[2], sys.argv[3])
        elif len(sys.argv) < 4:
            print("Usage: send_email.py <email_address>")
        else:
            send_email(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    except IndexError:
        print("Usage: send_email.py <email_address> <name> <username> <password>")
        print("Admin Usage : send_email.py --Admin-alert <log_file_path>")



