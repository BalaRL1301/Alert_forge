import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import threading

logger = logging.getLogger("AlertForgeEmail")

class EmailService:
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager

    def send_email_async(self, subject, body, to_email):
        """Runs the email sending in a separate thread to be non-blocking."""
        thread = threading.Thread(target=self._send_email_thread, args=(subject, body, to_email))
        thread.start()

    def _send_email_thread(self, subject, body, to_email):
        settings = self.settings_manager.get_all()
        
        smtp_server = settings.get("smtp_server")
        smtp_port = settings.get("smtp_port")
        smtp_username = settings.get("smtp_username")
        smtp_password = settings.get("smtp_password")

        if not all([smtp_server, smtp_port, smtp_username, smtp_password]):
            logger.error("Missing SMTP configuration. Cannot send email.")
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_username
            msg['To'] = to_email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(smtp_server, int(smtp_port))
            server.starttls()
            server.login(smtp_username, smtp_password)
            text = msg.as_string()
            server.sendmail(smtp_username, to_email, text)
            server.quit()
            
            logger.info(f"Email sent successfully to {to_email}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")

    def send_alert(self, alert_details):
        settings = self.settings_manager.get_all()
        to_email = settings.get("admin_email")
        
        if not to_email:
            logger.warning("No admin email configured. Skipping alert email.")
            return

        subject = f"AlertForge: {alert_details['type']} Detected!"
        body = f"""
AlertForge Security Alert
-------------------------
Type: {alert_details['type']}
Classification: {alert_details['classification']}
Confidence: {alert_details['confidence']}
Source IP: {alert_details.get('source_ip', 'Unknown')}
Time: {alert_details.get('timestamp')}

Details:
{alert_details.get('details')}

-------------------------
This is an automated message from your AlertForge System.
"""
        self.send_email_async(subject, body, to_email)
