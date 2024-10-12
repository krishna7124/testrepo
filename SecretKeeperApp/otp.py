import random
import smtplib
from email.mime.text import MIMEText
import logging
import streamlit as st

# Generate a random OTP

email_user = st.secrets["smtp"]["email_user"]
email_password = st.secrets["smtp"]["email_password"]

def generate_otp():
    otp = random.randint(100000, 999999)  # 6-digit OTP
    logging.info(f"Generated OTP: {otp}")
    return otp

# Send OTP via email


def send_otp_via_email(recipient_email, otp):
    try:
        msg = MIMEText(f"Your OTP for verification is: {otp}")
        msg['Subject'] = 'Your OTP Code'
        msg['From'] = 'krishnabhatt340@gmail.com'  # Sender's email
        msg['To'] = recipient_email

        # Gmail SMTP server details
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(email_user, email_password)  # Use App Password
            server.send_message(msg)

        logging.info(f"OTP sent successfully to {recipient_email}")
        return True
    except Exception as e:
        logging.error(f"Failed to send OTP: {e}")
        return False


# # For Testing OTP Functionality
# # generate_otp()
# test_otp = generate_otp()
# send_otp_via_email('krishnabhatt268@gmail.com', test_otp)

# print(test_otp)

# a = int(input(print("Enter OTP: ")))

# if a == test_otp:
#     print("Otp Entered is correc")
# else:
#     print("Invalid otp")
