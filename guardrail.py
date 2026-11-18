import ipaddress
import json
import os
import re
import socket
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

class GuardrailProxy:
    def __init__(self, policy_path="policy.json", log_path="security_audit.log", headless_mode=False):
        with open(policy_path, "r") as f:
            self.policy = json.load(f)
        self.log_path = log_path
        self.headless_mode = headless_mode
        self.session_tainted = False
        self.tool_call_count = 0

    def reset_session(self):
        self.session_tainted = False
        self.tool_call_count = 0
        self._log("INFO", "Session state reset (taint cleared, call counter = 0).")

    def _log(self, level, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}"
        print(entry)
        with open(self.log_path, "a") as f:
            f.write(entry + "\n")

    def _contains_sensitive_data(self, text):
        patterns = self.policy.get("dlp_blocked_patterns", [])
        for pattern in patterns:
            if re.search(pattern, text):
                return True, pattern
        return False, None

    def execute_tool(self, tool_name, **kwargs):
        # Week 2 Check 1: Rate Limiting (Infinite Loop Protection)
        self.tool_call_count += 1
        max_calls = self.policy.get("max_tool_calls_per_session", 5)
        if self.tool_call_count > max_calls:
            self._log("BLOCKED", f"Rate limit exceeded! Call #{self.tool_call_count} blocked (max {max_calls}).")
            return f"ERROR: Rate limit exceeded (max {max_calls} tool calls per session)."

        self._log("INFO", f"Intercepted tool call (#{self.tool_call_count}): {tool_name}({kwargs})")

        if tool_name == "read_file":
            return self._handle_read_file(kwargs.get("filename", ""))
        elif tool_name == "send_email":
            return self._handle_send_email(kwargs.get("to", ""), kwargs.get("content", ""))
        elif tool_name == "query_db":
            return self._handle_query_db(kwargs.get("sql", ""))
        elif tool_name == "fetch_url":
            return self._handle_fetch_url(kwargs.get("url", ""))
        else:
            self._log("BLOCKED", f"Unknown or unauthorized tool '{tool_name}'.")
            return f"ERROR: Tool '{tool_name}' is not permitted."

    def _handle_read_file(self, filename):
        base_name = os.path.basename(filename)

        if base_name in self.policy["blocked_files"]:
            self._log("BLOCKED", f"Attempted access to restricted file: '{filename}'")
            return "ERROR: Security policy forbids reading this file."

        allowed_dir = os.path.abspath(self.policy["allowed_directory"])
        requested_path = os.path.abspath(os.path.join(allowed_dir, filename))

        if not requested_path.startswith(allowed_dir):
            self._log("BLOCKED", f"Path traversal attempt detected: '{filename}'")
            return "ERROR: Access outside the safe workspace is forbidden."

        if not os.path.exists(requested_path):
            return f"ERROR: File '{filename}' not found."

        if base_name in self.policy["untrusted_files"]:
            self._log("WARNING", f"Untrusted file '{base_name}' read. Session marked TAINTED.")
            self.session_tainted = True

        with open(requested_path, "r") as f:
            return f.read()

    def _handle_send_email(self, to, content):
        if self.session_tainted:
            self._log("BLOCKED", f"Taint violation! Blocked email to '{to}' after reading untrusted data.")
            return "ERROR: Outbound actions are locked because this session processed untrusted data."

        allowed_domains = self.policy["allowed_email_domains"]
        if not any(to.endswith(domain) for domain in allowed_domains):
            self._log("BLOCKED", f"Unauthorized recipient '{to}'. Allowed: {allowed_domains}")
            return "ERROR: Recipient domain is not on the approved allowlist."

        max_len = self.policy.get("max_email_length", 2000)
        if len(content) > max_len:
            self._log("BLOCKED", f"Payload too large ({len(content)} chars > max {max_len}).")
            return f"ERROR: Email content exceeds maximum allowed length of {max_len} characters."

        has_secret, matched_pattern = self._contains_sensitive_data(content)
        if has_secret:
            self._log("BLOCKED", f"DLP VIOLATION! Outbound email to '{to}' matched secret pattern: {matched_pattern}")
            return "ERROR: DLP policy blocked this email because it contains sensitive credentials or secrets."

        if self.policy.get("require_approval_for_emails", False):
            if self.headless_mode:
                self._log("BLOCKED", f"Headless API mode: email to '{to}' held pending human operator approval.")
                return "ERROR: Action requires interactive human approval (blocked in headless API mode)."
            choice = input(f"\n[APPROVAL REQUIRED] Allow AI to email '{to}'? (y/n): ").strip().lower()
            if choice != "y":
                self._log("BLOCKED", f"Human operator denied email to '{to}'.")
                return "ERROR: Action denied by human operator."

        self._log("ALLOWED", f"Email sent to '{to}' | Content: {content}")
        return f"SUCCESS: Email sent to {to}."

    def _handle_query_db(self, sql):
        cleaned = sql.strip()
        upper_sql = cleaned.upper()

        if ";" in cleaned.rstrip(";"):
            self._log("BLOCKED", f"SQL stacked query attempt blocked: '{sql}'")
            return "ERROR: Multiple SQL statements are forbidden."

        if not upper_sql.startswith("SELECT "):
            self._log("BLOCKED", f"Non-SELECT SQL statement blocked: '{sql}'")
            return "ERROR: Only read-only SELECT queries are permitted."

        blocked_tables = self.policy.get("blocked_db_tables", [])
        for table in blocked_tables:
            if re.search(rf"\b{re.escape(table)}\b", cleaned, re.IGNORECASE):
                self._log("BLOCKED", f"Access to restricted DB table '{table}' blocked: '{sql}'")
                return f"ERROR: Access to table '{table}' is forbidden by security policy."

        db_path = self.policy.get("database_path", "company.db")
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cur = conn.cursor()
            cur.execute(cleaned)
            rows = cur.fetchall()
            conn.close()
            self._log("ALLOWED", f"Executed safe SQL query: '{sql}' -> {len(rows)} rows")
            return str(rows)
        except sqlite3.Error as e:
            self._log("BLOCKED", f"SQL execution error: {e}")
            return f"ERROR: Database query failed ({e})."

    def _handle_fetch_url(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            self._log("BLOCKED", f"Invalid or unsafe URL scheme blocked: '{url}'")
            return "ERROR: Only valid HTTP/HTTPS URLs are permitted."

        hostname = parsed.hostname.lower()

        if hostname in ("localhost", "127.0.0.1", "::1"):
            self._log("BLOCKED", f"SSRF localhost attempt blocked: '{url}'")
            return "ERROR: Access to localhost/loopback addresses is forbidden."

        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                self._log("BLOCKED", f"SSRF internal IP ({resolved_ip}) blocked for '{url}'")
                return "ERROR: Access to private or internal network addresses is forbidden."
        except socket.gaierror:
            pass

        allowed_domains = self.policy.get("allowed_url_domains", [])
        if hostname not in allowed_domains:
            self._log("BLOCKED", f"Unapproved URL domain '{hostname}' blocked. Allowed: {allowed_domains}")
            return "ERROR: URL domain is not on the approved allowlist."

        self._log("WARNING", f"External URL '{url}' fetched. Session marked TAINTED.")
        self.session_tainted = True
        self._log("ALLOWED", f"Fetched approved URL: '{url}'")
        return f"SUCCESS: Simulated response from {url} (Session now TAINTED)."
