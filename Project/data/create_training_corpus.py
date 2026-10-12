"""
Training Corpus Generator

Creates a balanced training corpus of phishing emails (derived from Nazario corpus
and real-world phishing patterns) and legitimate emails (derived from Enron
and standard business/personal communication).
"""

import json
import os

TRAINING_DATA = [
    # --- PHISHING SAMPLES (Label: 1) ---
    {
        "label": 1,
        "from_raw": "PayPal Security <service-notice@paypal-account-verify.xyz>",
        "subject": "URGENT: Your PayPal Account Has Been Suspended",
        "body": "Dear Customer,\n\nWe detected unauthorized activity on your PayPal account. For your protection, your access has been temporarily restricted. You must verify your identity within 24 hours or your account will be permanently closed.\n\nClick the link below to confirm your credentials and update your credit card details:\nhttp://paypal-account-verify.xyz/login\n\nThank you,\nPayPal Support Team",
        "reply_to": "divert-box@yahoo.com",
        "return_path": "bounce@paypal-account-verify.xyz",
        "auth_results": "spf=fail (sender IP not authorized) dkim=fail",
        "received_spf": "Fail",
        "received_hops": 4,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "Microsoft 365 Security <admin@office365-verify-portal.tk>",
        "subject": "Action Required: Password Expiry Notification",
        "body": "Attention User,\n\nYour Office 365 password will expire today. Immediate action is required to prevent loss of email access. Log in to verify your password and keep your existing credentials active.\n\nAccess the portal: http://192.168.1.105/auth/office\n\nIf you fail to respond, your mailbox will be locked immediately.",
        "reply_to": "admin@office365-verify-portal.tk",
        "return_path": "bounce@office365-verify-portal.tk",
        "auth_results": "spf=softfail dkim=none",
        "received_spf": "SoftFail",
        "received_hops": 3,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "DHL Express Tracking <tracking@dhl-package-tracking-portal.com>",
        "subject": "Delivery Exception: Your Parcel Could Not Be Delivered",
        "body": "Dear Client,\n\nYour shipment #DHL-984210 cannot be delivered due to an incorrect shipping address and unpaid customs fees of $3.50. You must download and complete the attached delivery form to confirm your address within 24 hours.\n\nPlease review the attached document.\n\nDHL International GmbH",
        "reply_to": "support@dhl-package-tracking-portal.com",
        "return_path": "mail@dhl-package-tracking-portal.com",
        "auth_results": "spf=fail dkim=fail",
        "received_spf": "Fail",
        "received_hops": 5,
        "attachments": [{"filename": "DHL_Delivery_Receipt.pdf.exe", "content_type": "application/x-dosexec", "size_bytes": 1048576}]
    },
    {
        "label": 1,
        "from_raw": "Chase Online Banking <alert@chase-secure-banking-logon.com>",
        "subject": "Security Alert: Unusual Sign-In Attempt Detected",
        "body": "Dear Valued Customer,\n\nWe detected a sign-in attempt from an unrecognized device in Moscow, Russia. If this was not you, immediate verification is needed. Enter your account number, SSN, and debit card PIN to restore complete access.\n\nConfirm identity now: http://bit.ly/chase-auth-alert\n\nChase Bank Fraud Prevention Unit",
        "reply_to": "stealer@yandex.com",
        "return_path": "bounce@chase-secure-banking-logon.com",
        "auth_results": "spf=fail dkim=none dmarc=fail",
        "received_spf": "Fail",
        "received_hops": 4,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "Apple Support <id-verify@secure-appleid-verify.com>",
        "subject": "Your Apple ID has been locked for security reasons",
        "body": "Dear Customer,\n\nSomeone tried to reset your Apple ID password multiple times. Your account has been temporarily disabled. To unlock your account, click the link below and confirm your personal information:\n\nhttps://id.apple.com.verify-user-account.tk/signin\n\nApple Support Team",
        "reply_to": "id-verify@secure-appleid-verify.com",
        "return_path": "id-verify@secure-appleid-verify.com",
        "auth_results": "spf=softfail dkim=none",
        "received_spf": "SoftFail",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "Internal Revenue Service <refund@irs-tax-refund-claim.org>",
        "subject": "Tax Refund Notification: $1,450.00 Ready for Direct Deposit",
        "body": "Dear Taxpayer,\n\nAfter calculating your annual tax return, we determined you are eligible for an uncollected refund payment of $1,450.00. Please submit the tax refund request form immediately by clicking below:\n\nhttp://credential-harvester.buzz/irs-claim\n\nEnter your social security number and bank account details.",
        "reply_to": "claims@gmail.com",
        "return_path": "mailer@irs-tax-refund-claim.org",
        "auth_results": "spf=fail dkim=none dmarc=fail",
        "received_spf": "Fail",
        "received_hops": 6,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "Netflix Billing <billing@netflix-billing-update.xyz>",
        "subject": "We were unable to process your recent membership payment",
        "body": "Hi,\n\nWe are having trouble with your current billing information. We tried to authorize your card but it failed. Please update your payment card within 48 hours to prevent termination of your subscription.\n\nUpdate billing: http://netflix-billing-update.xyz/pay\n\nThe Netflix Team",
        "reply_to": "billing@netflix-billing-update.xyz",
        "return_path": "bounce@netflix-billing-update.xyz",
        "auth_results": "spf=softfail dkim=fail",
        "received_spf": "SoftFail",
        "received_hops": 3,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "Amazon Orders <orders-update@paypa1-security-update.com>",
        "subject": "Order Confirmation #403-9182391: MacBook Pro 16",
        "body": "Dear Amazon Customer,\n\nThank you for your order of MacBook Pro M3 ($2,499.00). If you did not make this purchase, contact our fraud department immediately or cancel the transaction by downloading your order invoice:\n\nDownload order receipt: http://evil-tracker.com/invoice.docm\n\nCustomer Care Services",
        "reply_to": "fraud-hotline@outlook.com",
        "return_path": "bounce@paypa1-security-update.com",
        "auth_results": "spf=fail dkim=none",
        "received_spf": "Fail",
        "received_hops": 4,
        "attachments": [{"filename": "Amazon_Invoice_40391.docm", "content_type": "application/vnd.ms-word.document.macroEnabled.12", "size_bytes": 450000}]
    },
    {
        "label": 1,
        "from_raw": "DocuSign System <service@docusign-envelope-review.com>",
        "subject": "Urgent: Please Sign Important Confidential Contract",
        "body": "Dear Member,\n\nAn urgent confidential legal document has been shared with you for electronic signature. Failure to review within 12 hours will incur legal penalties.\n\nReview document: http://phish-site-sample.cc/sign\n\nDocuSign Signing Service",
        "reply_to": "service@docusign-envelope-review.com",
        "return_path": "bounce@docusign-envelope-review.com",
        "auth_results": "spf=fail dkim=none",
        "received_spf": "Fail",
        "received_hops": 3,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "Bank of America <security@bofa-alert-protection.biz>",
        "subject": "Immediate Action Required: Wire Transfer Blocked",
        "body": "Dear Customer,\n\nA wire transfer of $4,800.00 was attempted from your checking account. To reject or confirm this charge, verify your account details promptly.\n\nVerify Account: http://update-payment-card.shop/bofa\n\nBank of America Fraud Protection",
        "reply_to": "help@bofa-alert-protection.biz",
        "return_path": "bounce@bofa-alert-protection.biz",
        "auth_results": "spf=softfail dkim=fail",
        "received_spf": "SoftFail",
        "received_hops": 3,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "Barrister Robert Cole <robert.cole@legal-trustees.org>",
        "subject": "CONFIDENTIAL: Unclaimed Inheritance Fund of $8.5 Million USD",
        "body": "Dear Friend,\n\nI am the personal attorney to a deceased client who left an unclaimed estate of $8.5M. Since you share the same surname, I propose presenting you as the legal next of kin. Reply immediately with your full name, telephone, and passport copy to initiate wire transfer.",
        "reply_to": "robertcole998@gmail.com",
        "return_path": "info@legal-trustees.org",
        "auth_results": "spf=none dkim=none",
        "received_spf": "Neutral",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 1,
        "from_raw": "IT Helpdesk <support@company-portal-auth.tk>",
        "subject": "System Upgrade: All employees must re-validate webmail",
        "body": "Attention Employee,\n\nOur corporate email migration requires every staff member to validate their login credentials. Accounts not validated by midnight will be terminated.\n\nClick here: http://192.168.100.23/portal/login\n\nCorporate IT Department",
        "reply_to": "support@company-portal-auth.tk",
        "return_path": "mailer@company-portal-auth.tk",
        "auth_results": "spf=fail dkim=none",
        "received_spf": "Fail",
        "received_hops": 2,
        "attachments": []
    },

    # --- LEGITIMATE SAMPLES (Label: 0) ---
    {
        "label": 0,
        "from_raw": "GitHub <noreply@github.com>",
        "subject": "[GitHub] A personal access token has been generated",
        "body": "Hi rohin,\n\nA new personal access token (classic) was recently created for your account.\n\nToken name: cli-development-token\nScopes: repo, read:user\n\nIf you did not generate this token, please visit your account settings at https://github.com/settings/tokens to revoke it immediately.\n\nThanks,\nThe GitHub Team",
        "reply_to": "noreply@github.com",
        "return_path": "noreply@github.com",
        "auth_results": "spf=pass (google.com: domain of noreply@github.com designates 192.30.252.204 as permitted sender) dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 0,
        "from_raw": "Google Calendar <calendar-notification@google.com>",
        "subject": "Invitation: Team Sprint Planning @ Mon Oct 19, 2026 10am - 11am (IST)",
        "body": "You have been invited to the following event.\n\nTeam Sprint Planning\nWhen: Monday Oct 19, 2026 10:00am - 11:00am\nWhere: Google Meet (meet.google.com/abc-defg-hij)\n\nOrganizer: alex@corp.company.com\n\nView your calendar: https://calendar.google.com/calendar",
        "reply_to": "calendar-notification@google.com",
        "return_path": "calendar-notification@google.com",
        "auth_results": "spf=pass dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 0,
        "from_raw": "David Miller <david.miller@enron.com>",
        "subject": "Q3 Power Trading Risk Assessment & Pipeline Status",
        "body": "Hi team,\n\nAttached is the revised risk assessment sheet for our regional power trading desks across the Midwest pipeline. Please look through the volumetric exposures on tab 2 prior to tomorrow afternoon's committee meeting.\n\nLet me know if you have any questions.\n\nBest regards,\nDavid Miller\nEnron North America",
        "reply_to": "david.miller@enron.com",
        "return_path": "david.miller@enron.com",
        "auth_results": "spf=pass dkim=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": [{"filename": "Q3_Risk_Assessment.xlsx", "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "size_bytes": 84500}]
    },
    {
        "label": 0,
        "from_raw": "LinkedIn <messages-noreply@linkedin.com>",
        "subject": "Sarah Jenkins endorsed you for Python and Machine Learning",
        "body": "Hi Rohin,\n\nSarah Jenkins recognized your skills! See who else has viewed your profile this week:\n\nhttps://www.linkedin.com/in/skills\n\nKeep expanding your network on LinkedIn.\n\nUnsubscribe from these emails: https://www.linkedin.com/e/unsubscribe",
        "reply_to": "messages-noreply@linkedin.com",
        "return_path": "messages-noreply@linkedin.com",
        "auth_results": "spf=pass dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 0,
        "from_raw": "Amazon.com Customer Service <auto-confirm@amazon.com>",
        "subject": "Your order #112-9842109-192301 has shipped",
        "body": "Hello,\n\nWe are pleased to inform you that your package containing 'Python Data Science Handbook' has been dispatched via UPS. Estimated delivery is Wednesday, October 14.\n\nTrack your package anytime by visiting your orders: https://www.amazon.com/gp/css/order-history\n\nThank you for shopping with Amazon!",
        "reply_to": "auto-confirm@amazon.com",
        "return_path": "auto-confirm@amazon.com",
        "auth_results": "spf=pass dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 0,
        "from_raw": "Netflix <info@mailer.netflix.com>",
        "subject": "Coming Soon: New Releases on Netflix this November",
        "body": "Hi there,\n\nHere is a sneak peek at upcoming movies and series arriving next month on Netflix. Check out the trailers and add your favorite titles to My List.\n\nBrowse upcoming titles: https://www.netflix.com/browse\n\nQuestions? Visit the Netflix Help Center at https://help.netflix.com",
        "reply_to": "info@mailer.netflix.com",
        "return_path": "info@mailer.netflix.com",
        "auth_results": "spf=pass dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 0,
        "from_raw": "Sarah Connor <sarah.connor@university.edu>",
        "subject": "Lecture Notes and Reading Assignment for Chapter 5",
        "body": "Dear Students,\n\nHere are the slides from today's lecture on distributed systems architecture. Please make sure to complete the reading assignment in chapter 5 before next Tuesday's seminar.\n\nThe PDF slides are attached.\n\nProfessor Sarah Connor\nDepartment of Computer Science",
        "reply_to": "sarah.connor@university.edu",
        "return_path": "sarah.connor@university.edu",
        "auth_results": "spf=pass dkim=pass",
        "received_spf": "Pass",
        "received_hops": 1,
        "attachments": [{"filename": "Lecture_05_Distributed_Systems.pdf", "content_type": "application/pdf", "size_bytes": 1420000}]
    },
    {
        "label": 0,
        "from_raw": "Stripe Receipts <receipts@stripe.com>",
        "subject": "Your receipt for Cloud Hosting Services ($24.00)",
        "body": "Receipt from Cloud Infrastructure Inc.\nAmount paid: $24.00\nPayment method: Visa ending in 4242\nDate: October 10, 2026\n\nView invoice online: https://invoice.stripe.com/i/acct_123/inv_456\n\nIf you have any questions, reach out to support@cloudinfra.io.",
        "reply_to": "receipts@stripe.com",
        "return_path": "receipts@stripe.com",
        "auth_results": "spf=pass dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 0,
        "from_raw": "Slack Technologies <notifications@slack.com>",
        "subject": "New messages in #engineering-core",
        "body": "You have 3 unread messages in #engineering-core from Alex, Jamie, and Priya.\n\nAlex: 'PR #418 is ready for review, tests passing.'\n\nOpen Slack: https://slack.com/app\n\nManage notification preferences in your Slack profile.",
        "reply_to": "notifications@slack.com",
        "return_path": "notifications@slack.com",
        "auth_results": "spf=pass dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 0,
        "from_raw": "The New York Times <newsletters@nytimes.com>",
        "subject": "The Morning: Key Developments in Global Science and Tech",
        "body": "Good morning.\n\nToday in technology: Researchers discover new algorithmic bounds in quantum cryptography. Read today's full edition online:\n\nhttps://www.nytimes.com/section/technology\n\nYou received this newsletter because you are subscribed to The Morning. Manage your preferences at https://www.nytimes.com/email",
        "reply_to": "newsletters@nytimes.com",
        "return_path": "newsletters@nytimes.com",
        "auth_results": "spf=pass dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    },
    {
        "label": 0,
        "from_raw": "HR Department <hr@enterprise-solutions.com>",
        "subject": "Annual Benefits Enrollment Opens Next Monday",
        "body": "Hello Everyone,\n\nOur open enrollment period for healthcare, dental, and retirement plans begins next Monday, October 19. You can review the benefits plan comparison guide on our internal intranet.\n\nIntranet: https://intranet.enterprise-solutions.com/benefits\n\nBest,\nHuman Resources",
        "reply_to": "hr@enterprise-solutions.com",
        "return_path": "hr@enterprise-solutions.com",
        "auth_results": "spf=pass dkim=pass",
        "received_spf": "Pass",
        "received_hops": 1,
        "attachments": [{"filename": "2027_Benefits_Guide.pdf", "content_type": "application/pdf", "size_bytes": 620000}]
    },
    {
        "label": 0,
        "from_raw": "Apple Store <order-update@apple.com>",
        "subject": "Your Apple Store order #W84910283 is processing",
        "body": "Hello,\n\nThank you for ordering with Apple. We are preparing your order for shipment. We will send another email with tracking info as soon as it leaves our warehouse.\n\nView order status: https://www.apple.com/shop/order/status\n\nApple Inc., One Apple Park Way, Cupertino, CA 95014",
        "reply_to": "order-update@apple.com",
        "return_path": "order-update@apple.com",
        "auth_results": "spf=pass dkim=pass dmarc=pass",
        "received_spf": "Pass",
        "received_hops": 2,
        "attachments": []
    }
]

def generate_corpus():
    data_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(data_dir, "training_corpus.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(TRAINING_DATA, f, indent=2)
    print(f"Generated training corpus with {len(TRAINING_DATA)} samples at {out_path}")

if __name__ == "__main__":
    generate_corpus()
