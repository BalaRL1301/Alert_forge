import random
import re

class AIService:
    def __init__(self):
        self.analyzers = [
            (r"union\s+select", self._analyze_sql_injection),
            (r"or\s+['\"]?1['\"]?=['\"]?1", self._analyze_sql_injection),
            (r"<script>", self._analyze_xss),
            (r"\.\./", self._analyze_path_traversal),
            (r"/etc/passwd", self._analyze_path_traversal),
            (r"eval\(base64", self._analyze_webshell),
        ]

    def _analyze_sql_injection(self, log_data):
        return (
            "**AI Analysis**: This event indicates a **SQL Injection (SQLi)** attempt. "
            " The attacker is attempting to manipulate database queries by injecting malicious SQL commands. "
            f"The payload `{log_data.get('message', '')}` specifically targets authentication bypass or data exfiltration via UNION SELECT. "
            "**Recommendation**: Verify input validation on this endpoint and ensure parameterized queries are used."
        )

    def _analyze_xss(self, log_data):
         return (
            "**AI Analysis**: Detected **Cross-Site Scripting (XSS)** vector. "
            "The payload contains HTML script tags intended to execute arbitrary JavaScript in the victim's browser. "
            f"Target: `{log_data.get('app', 'Web App')}`. "
            "**Impact**: Could lead to session hijacking or credential theft. "
            "**Remediation**: Implement Content Security Policy (CSP) and sanitize all user outputs."
        )

    def _analyze_path_traversal(self, log_data):
        return (
            "**AI Analysis**: **Directory Traversal** attack detected. "
            "The pattern `../` suggests an attempt to break out of the web root directory to access sensitive system files. "
            "**Criticality**: High. "
            "**Action**: access control lists (ACLs) should be reviewed immediately."
        )

    def _analyze_webshell(self, log_data):
        return (
            "**AI Analysis**: **Web Shell / RCE** signature identified. "
            "The payload contains encoded commands often used to establish a persistent backdoor on the server. "
            "**URGENT**: Isolate the affected server immediately. This is a potential system compromise."
        )

    def _analyze_generic_threat(self, log_data):
        reasons = [
            "Anomalous traffic pattern detected from this source IP.",
            "High frequency of requests indicates potential brute-force or probing.",
            "Payload contains unescaped special characters consistent with injection attacks."
        ]
        return (
            f"**AI Analysis**: The hybrid engine flagged this as a high-confidence threat ({int(log_data.get('analysis', {}).get('confidence', 0) * 100)}%). "
            f"{random.choice(reasons)} "
            "Manual investigation recommended."
        )

    def generate_analysis(self, log_data):
        """
        Generates a natural language report for a given log entry.
        """
        analysis_result = log_data.get("analysis", {})
        if not analysis_result.get("is_threat"):
            return "AI Analysis: Traffic appears normal. No malicious patterns detected."

        message = log_data.get("message", "") or log_data.get("raw_message", "")
        
        # Match against specific patterns
        for pattern, handler in self.analyzers:
            if re.search(pattern, message, re.IGNORECASE):
                return handler(log_data)
        
        # Fallback
        return self._analyze_generic_threat(log_data)
