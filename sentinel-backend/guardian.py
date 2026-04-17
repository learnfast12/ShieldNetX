import os
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

class GuardianAlert:
    def __init__(self):
        self.account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        self.auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        self.whatsapp_from = os.getenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
        self.sms_from = os.getenv("TWILIO_SMS_FROM", "")

    def send_alert(self, guardian_number: str, threat_score: int, url: str, threat_type: str) -> bool:
        if not self.account_sid or not self.auth_token:
            print("⚠️ Twilio not configured — skipping guardian alert")
            return False

        try:
            client = Client(self.account_sid, self.auth_token)
            message = (
                f"🚨 *SENTINEL ALERT*\n\n"
                f"Someone near you may have received a dangerous link!\n\n"
                f"🔴 Threat Level: *{threat_score}/100*\n"
                f"⚠️ Type: {threat_type}\n"
                f"🔗 Link: {url[:60]}...\n\n"
                f"Please check on your family member immediately.\n"
                f"— ShieldNetX 🛡️"
            )

            # Try WhatsApp first
            if guardian_number:
                wa_number = f"whatsapp:{guardian_number}" if not guardian_number.startswith("whatsapp:") else guardian_number
                client.messages.create(
                    body=message,
                    from_=self.whatsapp_from,
                    to=wa_number
                )
                print(f"✅ Guardian WhatsApp alert sent to {guardian_number}")
                return True

        except Exception as e:
            print(f"❌ Guardian alert failed: {str(e)}")
            # Try SMS fallback
            try:
                client = Client(self.account_sid, self.auth_token)
                client.messages.create(
                    body=message,
                    from_=self.sms_from,
                    to=guardian_number
                )
                return True
            except Exception as e2:
                print(f"❌ SMS fallback also failed: {str(e2)}")
                return False

        return False
