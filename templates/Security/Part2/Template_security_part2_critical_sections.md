# SECURITY TEMPLATE - PART 2: CRITICAL SECTIONS

## IMPORTANT: These sections MUST be added to the main TEMPLATE_security_exploitation.md

---

<a name="example-conversation"></a>
## 18. EXAMPLE FUTURE CONVERSATION

This section shows HOW you will use this template in the future when you ask me to create security tests.

### Example Conversation Flow

#### **YOU SAY:**
> "Quiero crear test_login_security.py para probar la página de login de una aplicación bancaria"

#### **I RESPOND:**
```
Perfecto, voy a crear el archivo de security para el módulo de Login.

Antes de empezar, déjame confirmar algunos detalles:

1. **Contexto del Módulo:**
   - Módulo: Login/Authentication
   - Tipo de aplicación: Banking
   - ¿Ya existen tests funcionales de login? [YES/NO]
   
2. **Vectores de Ataque a Testear:**
   Basándome en la matriz de research, para Login debo testear:
   - ✅ SQL Injection en username/password
   - ✅ Brute force protection
   - ✅ Session fixation
   - ✅ Weak password policy
   - ✅ Rate limiting
   - ✅ Account enumeration
   
   ¿Confirmas que quieres todos estos, o alguno específico?

3. **Entorno de Testing:**
   - URL: [necesito la URL del entorno de staging/demo]
   - ¿Tienes credenciales de prueba? [YES/NO]
   - Ambiente: ¿Demo/Staging/Test? (NO producción)

4. **Prioridad:**
   Para banking, los tests CRÍTICOS serán:
   - SQL Injection (CVSS 9.8)
   - Brute force sin rate limiting (CVSS 8.1)
   - Session fixation (CVSS 8.1)
   
   ¿Confirmas prioridades?

5. **Deliverables:**
   Voy a generar:
   - test_login_security.py (16-24 security tests)
   - README_login_security.md (documentación completa)
   - Todos los tests siguiendo filosofía DISCOVER
```

#### **YOU RESPOND:**
> "Sí, testea todos esos vectores. URL es https://demo-bank.com, tengo credenciales de prueba, es un entorno demo. Prioridad correcta."

#### **I DO:**
```
Perfecto, procediendo con la generación:

PASO 1 - RESEARCH:
Investigando estándares para Login/Authentication:
- OWASP ASVS v5.0 Chapter 2 (Authentication)
- NIST SP 800-63B (Digital Identity Guidelines)  
- ISO 27001 A.9.4 (Access Control)
- OWASP Top 10 2021 - A07 (Auth Failures)

PASO 2 - PLANNING:
Tests que voy a crear (20 tests):

Business Logic (3):
- TC-SEC-LOGIN-BL-001: Account enumeration
- TC-SEC-LOGIN-BL-002: Timing attack on authentication
- TC-SEC-LOGIN-BL-003: Password reset token predictability

Injection (4):
- TC-SEC-LOGIN-INJ-001: SQL Injection in username
- TC-SEC-LOGIN-INJ-002: SQL Injection in password
- TC-SEC-LOGIN-INJ-003: XSS in username field
- TC-SEC-LOGIN-INJ-004: LDAP injection (if applicable)

Bot Protection (3):
- TC-SEC-LOGIN-BOT-001: Brute force rate limiting
- TC-SEC-LOGIN-BOT-002: CAPTCHA after failed attempts
- TC-SEC-LOGIN-BOT-003: Account lockout mechanism

Authentication (4):
- TC-SEC-LOGIN-AUTH-001: Session fixation
- TC-SEC-LOGIN-AUTH-002: Session ID entropy
- TC-SEC-LOGIN-AUTH-003: Token regeneration on login
- TC-SEC-LOGIN-AUTH-004: Concurrent session handling

Password Policy (3):
- TC-SEC-LOGIN-PWD-001: Weak password acceptance
- TC-SEC-LOGIN-PWD-002: Password complexity requirements
- TC-SEC-LOGIN-PWD-003: Password history check

Data Exposure (3):
- TC-SEC-LOGIN-DATA-001: Credentials in client storage
- TC-SEC-LOGIN-DATA-002: Password in URL/logs
- TC-SEC-LOGIN-DATA-003: Error messages leaking info

PASO 3 - GENERATION:
Generando test_login_security.py...
[Genera el código siguiendo la plantilla]

PASO 4 - DOCUMENTATION:
Generando README_login_security.md...
[Genera el README]

PASO 5 - VALIDATION:
✅ Tests DESCUBREN (no asumen)
✅ Código reutilizable (cambiar URL + locators)
✅ Sin emojis, profesional
✅ Logging estructurado
✅ CVSS scores + standards
✅ Todos los tests con docstrings detallados

Archivos listos:
- test_login_security.py (20 security tests)
- README_login_security.md (documentación completa)
```

---

### Example 2: Payment Module

#### **YOU SAY:**
> "Genera test_payment_security.py para DemoBlaze"

#### **I RESPOND:**
```
Perfecto, módulo de Payment.

Confirmo que para Payment, según la matriz de research debo verificar:

CRÍTICO (PCI-DSS 4.0.1):
- Card data client-side storage (Req 3.2)
- CVV storage prohibition (Req 3.2)
- TLS version validation (Req 4.2)
- Payment script integrity (Req 11.6.1)

CRÍTICO (Business Logic):
- Price manipulation
- Negative amounts
- Currency tampering
- Race conditions on payment

¿Procedo con PCI-DSS compliance + business logic?
```

#### **YOU CONFIRM:**
> "Sí, procede"

#### **I GENERATE:**
```
Generando 24 tests:
- 4 PCI-DSS compliance tests (CRITICAL)
- 6 Business logic exploits (CRITICAL)
- 4 Injection tests in payment fields (HIGH)
- 3 Bot protection tests (HIGH)
- 4 Session/CSRF tests (HIGH)
- 3 Accessibility tests (MEDIUM)

Filosofía DISCOVER aplicada en cada test:
- Execute payment exploit
- Observe if exploit succeeds
- Decide if vulnerable objectively
- Log exploitation attempts
- Never assume DemoBlaze behavior
```

---

### Example 3: API Endpoints

#### **YOU SAY:**
> "Test security de endpoints API /api/users"

#### **I RESPOND:**
```
API Security - Checking research matrix:

Debo testear (OWASP API Security Top 10):
- API1: Broken Object Level Authorization (IDOR)
- API2: Broken Authentication
- API3: Broken Object Property Level Authorization
- API4: Unrestricted Resource Consumption
- API5: Broken Function Level Authorization
- API6: Unrestricted Access to Sensitive Business Flows

Specific tests:
- IDOR on /api/users/{id}
- Authentication token handling
- Rate limiting on API calls
- Response data exposure
- Mass assignment
- API enumeration

¿Necesitas también tests de API fuzzing o solo los básicos?
```

---

### Key Points From Examples

**What I Always Do:**
1. ✅ Confirm module type
2. ✅ Check research matrix
3. ✅ List critical vulnerabilities for that module
4. ✅ Confirm with you before generating
5. ✅ Generate code with DISCOVER philosophy
6. ✅ Create documentation
7. ✅ Validate against checklist

**What I Never Do:**
1. ❌ Generate code without confirming scope
2. ❌ Assume what you want
3. ❌ Create tests that assume site behavior
4. ❌ Skip documentation
5. ❌ Ignore standards

---

<a name="vulnerabilities-by-module"></a>
## 19. COMMON VULNERABILITIES BY MODULE TYPE

This is your quick reference for what to test based on module type.

### Authentication/Login Modules

**Critical Vulnerabilities:**
```
1. SQL Injection in Login Form
   CVSS: 9.8 CRITICAL
   Test: Inject "' OR '1'='1" in username/password
   Discovery: If login succeeds with SQL payload = vulnerable
   Standard: OWASP Top 10 - A03, OWASP ASVS v5.0-1.2.5

2. No Brute Force Protection
   CVSS: 8.1 HIGH  
   Test: Attempt 100+ login attempts rapidly
   Discovery: If no rate limiting/lockout = vulnerable
   Standard: OWASP ASVS v5.0-2.2.1, NIST 800-63B

3. Session Fixation
   CVSS: 8.1 HIGH
   Test: Check if session ID changes after login
   Discovery: If session ID unchanged = vulnerable
   Standard: OWASP Top 10 - A07, OWASP ASVS v5.0-3.2.1

4. Account Enumeration
   CVSS: 5.3 MEDIUM
   Test: Different error messages for valid/invalid users
   Discovery: If messages differ = information leakage
   Standard: OWASP ASVS v5.0-2.2.2

5. Weak Password Policy
   CVSS: 6.5 MEDIUM
   Test: Create account with password "123"
   Discovery: If accepted = weak policy
   Standard: NIST 800-63B Section 5.1.1
```

**Test Discovery Pattern:**
```python
# Always follow: EXECUTE → OBSERVE → DECIDE

# SQL Injection Discovery
inject_sql("' OR '1'='1")
result = observe_login_response()
if result.logged_in:
    pytest.fail("DISCOVERED: SQL Injection")

# Brute Force Discovery
for i in range(100):
    attempt_login("user", f"pass{i}")
    if rate_limited(i):
        break
if i >= 99:
    pytest.fail("DISCOVERED: No brute force protection")

# Session Fixation Discovery
session_before = get_session_id()
login("user", "pass")
session_after = get_session_id()
if session_before == session_after:
    pytest.fail("DISCOVERED: Session fixation")
```

---

### Payment/Checkout Modules

**Critical Vulnerabilities:**
```
1. Card Data Client-Side Storage
   CVSS: 10.0 CRITICAL
   Test: Fill card data, check localStorage/sessionStorage
   Discovery: If card number found in storage = PCI-DSS violation
   Standard: PCI-DSS 4.0.1 Requirement 3.2

2. CVV Storage Anywhere
   CVSS: 10.0 CRITICAL
   Test: Inject CVV into storage, check persistence
   Discovery: If CVV persists anywhere = PCI-DSS violation
   Standard: PCI-DSS 4.0.1 Requirement 3.2.1

3. Price Manipulation
   CVSS: 9.1 CRITICAL
   Test: Change price via JavaScript, complete checkout
   Discovery: If final price = manipulated price = vulnerable
   Standard: OWASP Top 10 - A04, OWASP WSTG-BUSL-10

4. TLS Version < 1.2
   CVSS: 8.1 HIGH
   Test: Check SSL/TLS version with requests
   Discovery: If TLS < 1.2 = PCI-DSS violation
   Standard: PCI-DSS 4.0.1 Requirement 4.2

5. No Card Number Validation
   CVSS: 7.5 HIGH
   Test: Submit "abcd" as card number
   Discovery: If accepted = validation failure
   Standard: PCI-DSS 4.0.1 Requirement 6.5.3
```

**Test Discovery Pattern:**
```python
# Card Storage Discovery
fill_card_form("4111111111111111")
storage = check_client_storage()
if "4111" in storage.localStorage:
    pytest.fail("DISCOVERED: PCI-DSS violation - card in storage")

# Price Manipulation Discovery
original_price = get_price()
change_price_javascript("0.01")
final_price = complete_checkout()
if final_price == 0.01:
    pytest.fail("DISCOVERED: Price manipulation")

# TLS Discovery
response = requests.get(url)
tls_version = get_tls_version(response)
if tls_version < TLS_1_2:
    pytest.fail("DISCOVERED: TLS too old")
```

---

### Shopping Cart Modules

**Critical Vulnerabilities:**
```
1. Negative Quantity Acceptance
   CVSS: 9.1 CRITICAL
   Test: Add item with quantity = -5
   Discovery: If negative quantity in cart = business logic flaw
   Standard: OWASP WSTG-BUSL-10

2. Integer Overflow
   CVSS: 7.5 HIGH
   Test: Add item with quantity = 2147483647 (max int32)
   Discovery: If accepted without validation = overflow vulnerability
   Standard: CWE-190

3. Race Condition on Add
   CVSS: 8.1 HIGH
   Test: Click "Add to Cart" 10 times concurrently
   Discovery: If all additions succeed = race condition
   Standard: CWE-362

4. Coupon Stacking
   CVSS: 6.5 MEDIUM
   Test: Apply same coupon multiple times
   Discovery: If multiple discounts applied = business logic flaw
   Standard: OWASP WSTG-BUSL-10

5. Cart Total Manipulation
   CVSS: 9.1 CRITICAL
   Test: Modify cart total via JavaScript
   Discovery: If checkout accepts manipulated total = vulnerable
   Standard: OWASP Top 10 - A04
```

**Test Discovery Pattern:**
```python
# Negative Quantity Discovery
add_to_cart(product_id=1, quantity=-5)
cart = get_cart_contents()
if any(item.quantity < 0 for item in cart):
    pytest.fail("DISCOVERED: Negative quantities accepted")

# Integer Overflow Discovery
add_to_cart(product_id=1, quantity=2147483647)
if not error_occurred():
    pytest.fail("DISCOVERED: Integer overflow not handled")

# Race Condition Discovery
results = concurrent_add_to_cart(times=10)
if sum(results) == 10:
    pytest.fail("DISCOVERED: Race condition")
```

---

### Search/Filter Modules

**Critical Vulnerabilities:**
```
1. SQL Injection in Search
   CVSS: 9.8 CRITICAL
   Test: Search for "' OR '1'='1"
   Discovery: If returns all results or database error = SQL injection
   Standard: OWASP Top 10 - A03, CWE-89

2. Stored XSS in Search History
   CVSS: 8.8 CRITICAL
   Test: Search for "<script>alert('XSS')</script>"
   Discovery: If script executes when viewing history = stored XSS
   Standard: OWASP Top 10 - A03, CWE-79

3. NoSQL Injection
   CVSS: 9.8 CRITICAL
   Test: Search for {"$ne": null}
   Discovery: If returns unintended results = NoSQL injection
   Standard: OWASP Top 10 - A03

4. LDAP Injection
   CVSS: 9.1 CRITICAL  
   Test: Search for "*)(objectClass=*"
   Discovery: If LDAP query manipulation = injection
   Standard: CWE-90

5. Reflected XSS
   CVSS: 7.1 HIGH
   Test: Search with XSS payload in URL parameter
   Discovery: If payload reflected without encoding = reflected XSS
   Standard: OWASP Top 10 - A03, CWE-79
```

**Test Discovery Pattern:**
```python
# SQL Injection in Search Discovery
results = search("' OR '1'='1")
if len(results) == total_products or "SQL error" in results:
    pytest.fail("DISCOVERED: SQL Injection in search")

# Stored XSS Discovery
search("<script>alert('XSS')</script>")
navigate_to_search_history()
if alert_triggered():
    pytest.fail("DISCOVERED: Stored XSS")

# NoSQL Injection Discovery
results = search('{"$ne": null}')
if len(results) > expected:
    pytest.fail("DISCOVERED: NoSQL Injection")
```

---

### User Profile Modules

**Critical Vulnerabilities:**
```
1. IDOR on Profile Access
   CVSS: 9.1 CRITICAL
   Test: Access /profile/123, then /profile/124 without auth
   Discovery: If can view other profiles = IDOR
   Standard: OWASP Top 10 - A01, CWE-639

2. XSS in Profile Fields
   CVSS: 8.8 CRITICAL
   Test: Set username to "<script>alert('XSS')</script>"
   Discovery: If script executes when profile viewed = stored XSS
   Standard: OWASP Top 10 - A03

3. Mass Assignment
   CVSS: 8.1 HIGH
   Test: Submit role=admin in profile update
   Discovery: If role changed = mass assignment
   Standard: CWE-915

4. PII Exposure in Responses
   CVSS: 7.5 HIGH
   Test: View page source, check API responses
   Discovery: If sensitive data in HTML/JSON = exposure
   Standard: OWASP Top 10 - A02

5. Profile Picture Upload RCE
   CVSS: 10.0 CRITICAL
   Test: Upload PHP file as image
   Discovery: If PHP executes = RCE
   Standard: CWE-434
```

**Test Discovery Pattern:**
```python
# IDOR Discovery
own_profile = get_profile(user_id=123)
other_profile = get_profile(user_id=124)
if other_profile.accessible:
    pytest.fail("DISCOVERED: IDOR vulnerability")

# Mass Assignment Discovery
update_profile(data={"role": "admin"})
new_profile = get_profile()
if new_profile.role == "admin":
    pytest.fail("DISCOVERED: Mass assignment")

# PII Exposure Discovery
response = api_call("/api/profile/123")
if contains_pii(response, ["ssn", "creditcard"]):
    pytest.fail("DISCOVERED: PII exposure")
```

---

### Admin Panel Modules

**Critical Vulnerabilities:**
```
1. Missing Authorization Checks
   CVSS: 9.1 CRITICAL
   Test: Access /admin as regular user
   Discovery: If admin panel accessible = broken access control
   Standard: OWASP Top 10 - A01

2. Privilege Escalation
   CVSS: 9.8 CRITICAL
   Test: Modify role parameter to admin
   Discovery: If role change succeeds = privilege escalation
   Standard: CWE-269

3. CSRF on Admin Actions
   CVSS: 8.1 HIGH
   Test: Submit admin action without CSRF token
   Discovery: If action succeeds = CSRF vulnerability
   Standard: OWASP Top 10 - A01

4. IDOR on Admin Functions
   CVSS: 9.1 CRITICAL
   Test: Delete user with /admin/delete/user/{other_user_id}
   Discovery: If deletion succeeds = IDOR
   Standard: CWE-639

5. No Audit Logging
   CVSS: 6.5 MEDIUM
   Test: Perform admin actions, check logs
   Discovery: If no logging = monitoring failure
   Standard: OWASP Top 10 - A09
```

**Test Discovery Pattern:**
```python
# Authorization Discovery
logout()
response = access("/admin")
if response.status_code == 200:
    pytest.fail("DISCOVERED: Missing authorization")

# Privilege Escalation Discovery
update_user(user_id=123, role="admin")
if get_user(123).role == "admin":
    pytest.fail("DISCOVERED: Privilege escalation")

# CSRF Discovery
response = admin_action(csrf_token=None)
if response.success:
    pytest.fail("DISCOVERED: CSRF vulnerability")
```

---

### API Endpoints

**Critical Vulnerabilities:**
```
1. No Rate Limiting on API
   CVSS: 9.1 CRITICAL
   Test: Send 1000 API requests rapidly
   Discovery: If all succeed = no rate limiting
   Standard: OWASP API Security - API4

2. API Enumeration
   CVSS: 7.5 HIGH
   Test: Try /api/v1/users/1, /api/v1/users/2, etc.
   Discovery: If sequential IDs accessible = enumeration
   Standard: OWASP API Security - API1

3. Excessive Data Exposure
   CVSS: 8.1 HIGH
   Test: Call /api/users and check response
   Discovery: If response contains unnecessary PII = exposure
   Standard: OWASP API Security - API3

4. Broken Authentication
   CVSS: 9.8 CRITICAL
   Test: API call with invalid/no token
   Discovery: If succeeds = broken authentication
   Standard: OWASP API Security - API2

5. Mass Assignment
   CVSS: 8.1 HIGH
   Test: Send {"role": "admin"} in POST /api/users
   Discovery: If role set = mass assignment
   Standard: OWASP API Security - API6
```

**Test Discovery Pattern:**
```python
# Rate Limiting Discovery
for i in range(1000):
    response = api_call("/api/endpoint")
    if response.status_code == 429:
        break
if i >= 999:
    pytest.fail("DISCOVERED: No API rate limiting")

# Enumeration Discovery
user_ids = []
for id in range(1, 100):
    response = api_call(f"/api/users/{id}")
    if response.status_code == 200:
        user_ids.append(id)
if len(user_ids) > 50:
    pytest.fail("DISCOVERED: API enumeration possible")

# Excessive Data Exposure Discovery
response = api_call("/api/users/123")
if contains_sensitive_fields(response, ["ssn", "password_hash"]):
    pytest.fail("DISCOVERED: Excessive data exposure")
```

---

## Key Takeaway for All Modules

### Universal Discovery Pattern:

```python
"""Every security test follows this pattern regardless of module"""

def test_vulnerability(browser):
    """TC-SEC-[MOD]-[CAT]-001: Vulnerability Name
    
    Severity: CRITICAL/HIGH/MEDIUM/LOW
    CVSS: X.X
    Standard: [Specific standard]
    
    Discovers if [vulnerability] exists by [exploitation method]
    """
    
    # STEP 1: EXECUTE the exploit
    attempt_exploitation(browser, payload)
    
    # STEP 2: OBSERVE the response
    result = capture_response(browser)
    
    # STEP 3: DECIDE if vulnerable
    if result.indicates_vulnerability():
        # DISCOVERED: Vulnerable
        log_exploitation_attempt(
            vulnerability="Specific name",
            payload="Actual payload",
            result="Evidence of exploitation",
            standard="Standard violated"
        )
        pytest.fail("VULNERABILITY: Description")
    else:
        # DISCOVERED: Secure
        assert True
```

---

**End of Part 2**

**Integration Note:** These sections (18 and 19) should be inserted into the main TEMPLATE_security_exploitation.md file before the "Version History" section.