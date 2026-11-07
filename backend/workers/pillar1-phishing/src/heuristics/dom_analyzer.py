"""
DOM & Credential-Harvesting Heuristics Engine
Parses HTML/DOM trees for password inputs, payment cards, OTP fields, cross-origin form submissions,
Browser-in-the-Browser (BitB) OAuth windows, hidden iframes, and DevTools blockers.
"""
import re
import urllib.parse
from typing import Dict, Any, List, Optional
from html.parser import HTMLParser

class DOMHeuristicParser(HTMLParser):
    def __init__(self, base_domain: str):
        super().__init__()
        self.base_domain = base_domain.lower()
        self.password_inputs = 0
        self.payment_fields = 0
        self.otp_fields = 0
        self.hidden_iframes = 0
        self.cross_origin_submission: Optional[str] = None
        self.bitb_detected = False
        self.devtools_blocker = False
        self.current_form_action = None
        self.inline_scripts: List[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: List[tuple]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()

        # 1. Inspect Form Inputs
        if tag_lower == "form":
            action = attr_dict.get("action", "")
            if action:
                self.current_form_action = action
                # Check for cross-origin submission target
                parsed_action = urllib.parse.urlparse(action)
                if parsed_action.netloc and self.base_domain not in parsed_action.netloc.lower():
                    self.cross_origin_submission = action

        elif tag_lower == "input":
            input_type = attr_dict.get("type", "text").lower()
            name_attr = attr_dict.get("name", "").lower()
            id_attr = attr_dict.get("id", "").lower()
            placeholder = attr_dict.get("placeholder", "").lower()
            combined_meta = f"{name_attr} {id_attr} {placeholder}"

            if input_type == "password" or "password" in combined_meta or "pass" in combined_meta:
                self.password_inputs += 1

            if any(term in combined_meta for term in ["card", "cc-number", "cvv", "cvc", "creditcard", "cardnumber"]):
                self.payment_fields += 1

            if any(term in combined_meta for term in ["otp", "2fa", "mfa", "token", "verification", "code", "authenticator"]):
                self.otp_fields += 1

        # 2. Inspect Hidden Iframes
        elif tag_lower == "iframe":
            style = attr_dict.get("style", "").lower()
            width = attr_dict.get("width", "")
            height = attr_dict.get("height", "")
            if "display:none" in style or "opacity:0" in style or "visibility:hidden" in style or width in ("0", "1") or height in ("0", "1"):
                self.hidden_iframes += 1

        # 3. Detect Browser-in-the-Browser (BitB) Windows
        style = attr_dict.get("style", "").lower()
        class_name = attr_dict.get("class", "").lower()
        id_name = attr_dict.get("id", "").lower()
        if any(term in class_name or term in id_name for term in ["bitb", "modal-browser", "fake-window", "oauth-popup"]):
            self.bitb_detected = True
        if "cursor: default" in style and ("titlebar" in class_name or "browser-frame" in class_name):
            self.bitb_detected = True

        if tag_lower == "script":
            self._in_script = True

    def handle_endtag(self, tag: str):
        if tag.lower() == "script":
            self._in_script = False

    def handle_data(self, data: str):
        if self._in_script:
            self.inline_scripts.append(data)
            # Detect anti-debugging and DevTools blockers
            if any(term in data for term in [
                "debugger",
                "addEventListener('contextmenu'",
                'oncontextmenu="return false"',
                "keyCode === 123", # F12
                "ctrlKey && shiftKey && (e.keyCode === 73 || e.keyCode === 74)" # Ctrl+Shift+I / J
            ]):
                self.devtools_blocker = True

def analyze_html_dom(html_content: str, base_url: str) -> Dict[str, Any]:
    """Analyzes rendered HTML string for credential harvesting and anti-analysis heuristics."""
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.netloc.split(":")[0]

    parser = DOMHeuristicParser(base_domain)
    try:
        parser.feed(html_content)
    except Exception:
        pass

    # YARA / signature string matching for known phishing toolkits
    yara_matches = []
    suspicious_patterns = {
        "Evilginx2_Credential_Collector": r"evilginx|muraena|token_storage",
        "Generic_Microsoft_PhishKit": r"Sign in to your account|aad-login|login\.microsoftonline",
        "Telegram_Exfiltration_Bot": r"api\.telegram\.org/bot",
        "Discord_Webhook_Exfiltrator": r"discord\.com/api/webhooks",
    }

    full_text = html_content + " ".join(parser.inline_scripts)
    for rule_name, pattern in suspicious_patterns.items():
        if re.search(pattern, full_text, re.IGNORECASE):
            yara_matches.append(rule_name)

    return {
        "passwordInputsCount": parser.password_inputs,
        "paymentFieldsCount": parser.payment_fields,
        "otpFieldsCount": parser.otp_fields,
        "crossOriginSubmissionTarget": parser.cross_origin_submission,
        "browserInTheBrowserDetected": parser.bitb_detected,
        "hiddenIframesCount": parser.hidden_iframes,
        "devToolsBlockerDetected": parser.devtools_blocker,
        "yaraRulesMatched": yara_matches,
    }

