# FUNCTIONAL TEMPLATE - PART 2: CRITICAL SECTIONS

## IMPORTANT: These sections MUST be integrated with TEMPLATE_functional_business_rules_v2.md

---

<a name="example-conversations"></a>
## 18. EXAMPLE FUTURE CONVERSATIONS

This section shows HOW you will use this template when asking me to create functional and business rules tests.

### Example Conversation Flow

#### **SCENARIO 1: Login Module**

**YOU SAY:**
> "Quiero crear test_login.py para validar el login de una aplicación bancaria"

**I RESPOND:**
```
Perfecto, voy a crear los tests funcionales y de business rules para el módulo de Login.

Antes de empezar, déjame confirmar algunos detalles:

1. **Contexto del Módulo:**
   - Módulo: Login/Authentication
   - Tipo: Banking application
   - ¿Ya tienen tests existentes de login? [YES/NO]
   
2. **Alcance de Testing:**
   Basándome en la Research Matrix, para Login debo crear:
   
   **Functional Tests (6-8 tests):**
   - Valid credentials work
   - Invalid credentials rejected
   - Empty fields rejected
   - Login/logout flow
   - Remember me functionality
   - Password visibility toggle
   
   **Business Rules Tests (10-12 tests):**
   - Password strength policy (NIST 800-63B)
   - Input length validation (ISO 25010)
   - SQL injection prevention (OWASP ASVS 1.2.5)
   - XSS prevention (OWASP ASVS 1.2.1)
   - Error message accessibility (WCAG 3.3.1)
   - Whitespace normalization
   - Rate limiting check
   - Session fixation prevention
   - Brute force protection
   - Account enumeration prevention
   
   ¿Confirmas que quieres ambos tipos de tests?

3. **Entorno de Testing:**
   - URL: [necesito la URL del entorno de staging/demo]
   - ¿Tienes credenciales de prueba? [YES/NO]
   - Ambiente: ¿Demo/Staging/Test?

4. **Deliverables:**
   Voy a generar:
   - test_login.py (18-20 tests total: ~6 funcionales + ~12 business rules)
   - README_login.md (documentación completa)
   - Todos los tests siguiendo filosofía DISCOVER
```

**YOU RESPOND:**
> "Sí, ambos tipos. URL es https://demo-bank.com, tengo credenciales, es demo environment."

**I DO:**
```
Perfecto, procediendo con la generación:

PASO 1 - RESEARCH:
Investigando estándares para Login/Authentication:
- OWASP ASVS v5.0 Chapter 2 (Authentication)
- NIST SP 800-63B Section 5.1.1 (Password Guidelines)  
- ISO 27001 A.9.4 (Access Control)
- WCAG 2.1 Success Criterion 3.3.1 (Error Identification)

PASO 2 - PLANNING:
Tests que voy a crear (18 tests):

**FUNCTIONAL TESTS (6):**
TC-LOGIN-FUNC-001: Valid credentials login succeeds
TC-LOGIN-FUNC-002: Invalid password rejected
TC-LOGIN-FUNC-003: Invalid username rejected
TC-LOGIN-FUNC-004: Empty fields rejected
TC-LOGIN-FUNC-005: Login-logout flow works
TC-LOGIN-FUNC-006: Remember me functionality

**BUSINESS RULES TESTS (12):**
TC-LOGIN-BR-001: Input length validation (ISO 25010)
TC-LOGIN-BR-002: SQL injection prevention - username (OWASP ASVS 1.2.5)
TC-LOGIN-BR-003: SQL injection prevention - password (OWASP ASVS 1.2.5)
TC-LOGIN-BR-004: XSS prevention in username (OWASP ASVS 1.2.1)
TC-LOGIN-BR-005: Password strength policy (NIST 800-63B 5.1.1)
TC-LOGIN-BR-006: Error message accessibility (WCAG 3.3.1)
TC-LOGIN-BR-007: Whitespace normalization (ISO 25010)
TC-LOGIN-BR-008: Case sensitivity handling
TC-LOGIN-BR-009: Username validation format
TC-LOGIN-BR-010: Rate limiting check (Anti-automation)
TC-LOGIN-BR-011: Session fixation prevention (OWASP ASVS 3.2.1)
TC-LOGIN-BR-012: Account enumeration prevention

PASO 3 - GENERATION:
Generando test_login.py...
[Genera el código siguiendo la plantilla con filosofía DISCOVER]

PASO 4 - DOCUMENTATION:
Generando README_login.md...
[Genera el README completo]

PASO 5 - VALIDATION:
✅ Tests DESCUBREN (no asumen)
✅ Código reutilizable (cambiar URL + locators)
✅ Sin emojis, profesional
✅ Logging estructurado para violations
✅ Standards references con versiones
✅ Todos los tests con docstrings detallados

Archivos listos:
- test_login.py (18 tests: 6 functional + 12 business rules)
- README_login.md (documentación completa)
```

---

#### **SCENARIO 2: Payment Module**

**YOU SAY:**
> "Genera test_payment.py solo funcionales, no business rules todavía"

**I RESPOND:**
```
Entendido, solo tests funcionales para Payment.

Confirmando alcance:

**FUNCTIONAL TESTS (8 tests) - Happy Path:**
1. Valid card payment succeeds
2. Form submission works
3. Order confirmation appears
4. Payment flow completes end-to-end
5. Multiple items payment processes
6. Different card types work (Visa, Mastercard)
7. Cancel payment works
8. Return to cart works

**Business Rules:** NO (como solicitaste)

Información necesaria:
- URL: [necesito URL]
- Test card numbers: [necesito test cards]
- Environment: [Demo/Staging]

¿Procedo?
```

**YOU CONFIRM:**
> "Sí, procede. URL es https://demoblaze.com, usa test card 4111111111111111, demo environment"

**I GENERATE:**
```
Generando test_payment.py con 8 tests funcionales:

TC-PAYMENT-FUNC-001: Valid card payment succeeds
TC-PAYMENT-FUNC-002: Form submission works  
TC-PAYMENT-FUNC-003: Order confirmation shown
TC-PAYMENT-FUNC-004: Complete payment flow
TC-PAYMENT-FUNC-005: Multiple items payment
TC-PAYMENT-FUNC-006: Visa card works
TC-PAYMENT-FUNC-007: Mastercard works
TC-PAYMENT-FUNC-008: Payment cancellation

Todos los tests siguen filosofía DISCOVER:
- Execute payment action
- Observe result (success message, confirmation, etc.)
- Decide if feature works based on observation
- No assumptions about site behavior

Archivo listo: test_payment.py (8 functional tests)
```

---

#### **SCENARIO 3: Cart Module - Both Types**

**YOU SAY:**
> "Necesito tests completos de cart: funcionales y business rules"

**I RESPOND:**
```
Perfecto, suite completa para Shopping Cart.

Basándome en Research Matrix, voy a crear:

**FUNCTIONAL TESTS (8 tests):**
- Add to cart works
- Remove from cart works
- Update quantity works
- Cart total calculates correctly
- Empty cart works
- Continue shopping returns
- Proceed to checkout navigates
- Cart persists after navigation

**BUSINESS RULES TESTS (12 tests):**
- Quantity validation (ISO 25010)
  - Negative quantities rejected
  - Zero quantity rejected
  - Maximum quantity enforced
- Input length validation
- Price integrity validation
- Cart total recalculation accuracy
- XSS prevention in product names
- SQL injection prevention
- Session management (cart persistence)
- Concurrent modification handling
- Item availability checking
- Stock validation

Total: 20 tests

¿Procedo con esta configuración?
```

**YOU:**
> "Perfecto, adelante"

**I GENERATE:**
```
Generando test_cart.py...

20 tests creados:
- 8 functional (validate happy path)
- 12 business rules (validate standards compliance)

Filosofía DISCOVER aplicada:
- Add item → Observe if in cart → Decide if feature works
- Submit negative quantity → Observe rejection → Decide if validates
- Never assume cart behavior
- All tests work on any e-commerce site

Archivos:
- test_cart.py (20 tests)
- README_cart.md (comprehensive documentation)
```

---

### Key Points From Examples

**What I Always Do:**
1. ✅ Confirm module type
2. ✅ Check Research Matrix for relevant standards
3. ✅ List functional tests (happy path)
4. ✅ List business rules tests (standards)
5. ✅ Ask for URL, credentials, environment
6. ✅ Confirm with you before generating
7. ✅ Generate code with DISCOVER philosophy
8. ✅ Create documentation
9. ✅ Validate against checklist

**What I Never Do:**
1. ❌ Generate code without confirming scope
2. ❌ Assume what you want
3. ❌ Create tests that assume site behavior
4. ❌ Skip documentation
5. ❌ Ignore standards
6. ❌ Mix functional and business rules without clarity

---

<a name="common-patterns"></a>
## 19. COMMON PATTERNS BY MODULE TYPE

Quick reference showing typical test patterns for different module types.

### LOGIN/AUTHENTICATION MODULE

#### Functional Tests (Typical: 6 tests)

```python
@pytest.mark.functional
def test_valid_credentials_work():
    """Discovers if login succeeds with valid credentials"""
    login("validuser", "ValidPass123!")
    
    if is_logged_in():
        assert True  # DISCOVERED: Login works
    else:
        pytest.fail("DISCOVERED: Login broken")

@pytest.mark.functional
def test_invalid_password_rejected():
    """Discovers if invalid password is rejected"""
    login("validuser", "WrongPass")
    
    error = check_for_error()
    if error and "invalid" in error.lower():
        assert True  # DISCOVERED: Validates passwords
    else:
        pytest.fail("DISCOVERED: Doesn't validate passwords")

@pytest.mark.functional
def test_empty_fields_rejected():
    """Discovers if empty login is prevented"""
    login("", "")
    
    error = check_for_error()
    if error and "required" in error.lower():
        assert True  # DISCOVERED: Validates required fields
    else:
        pytest.fail("DISCOVERED: No empty field validation")
```

#### Business Rules Tests (Typical: 10-12 tests)

```python
@pytest.mark.business_rules
def test_password_strength_policy():
    """NIST 800-63B 5.1.1: Minimum 8 characters
    
    Discovers if system enforces password strength policy.
    """
    signup("user", "123")  # Weak password
    
    response = get_response()
    if "password" in response.lower() and "weak" in response.lower():
        assert True  # DISCOVERED: Enforces NIST policy
    else:
        log_violation(
            standard="NIST 800-63B Section 5.1.1",
            expected="Reject passwords < 8 chars",
            actual="Accepted '123'",
            severity="HIGH"
        )
        pytest.fail("DISCOVERED: Violates NIST 800-63B")

@pytest.mark.business_rules
@pytest.mark.parametrize("payload", ["' OR '1'='1", "admin'--"])
def test_sql_injection_prevention(payload):
    """OWASP ASVS 1.2.5: SQL Injection Prevention
    
    Discovers if SQL injection is possible in login form.
    """
    login(payload, "test")
    
    if login_succeeded():
        log_violation(
            standard="OWASP ASVS v5.0-1.2.5",
            expected="Block SQL injection",
            actual=f"SQL injection successful: {payload}",
            severity="CRITICAL"
        )
        pytest.fail("DISCOVERED: SQL Injection vulnerability")
    else:
        assert True  # DISCOVERED: SQL injection blocked

@pytest.mark.business_rules
def test_error_message_accessibility():
    """WCAG 2.1 SC 3.3.1: Error Identification
    
    Discovers if error messages are accessible (inline, not alerts).
    """
    login("", "")
    
    alert = check_for_alert()
    inline_error = check_for_inline_error()
    
    if alert:
        log_violation(
            standard="WCAG 2.1 Success Criterion 3.3.1",
            expected="Inline error messages",
            actual="JavaScript alert used",
            severity="MEDIUM"
        )
        pytest.fail("DISCOVERED: Uses inaccessible alerts")
    elif inline_error:
        assert True  # DISCOVERED: Accessible errors
```

---

### PAYMENT/CHECKOUT MODULE

#### Functional Tests (Typical: 8 tests)

```python
@pytest.mark.functional
def test_valid_payment_succeeds():
    """Discovers if valid card payment completes successfully"""
    fill_payment_form(
        card="4111111111111111",
        cvv="123",
        expiry="12/25"
    )
    submit_payment()
    
    confirmation = check_for_confirmation()
    if confirmation:
        assert True  # DISCOVERED: Payment works
    else:
        pytest.fail("DISCOVERED: Payment broken")

@pytest.mark.functional
def test_payment_cancellation_works():
    """Discovers if payment can be cancelled"""
    fill_payment_form(card="4111111111111111")
    click_cancel()
    
    if returned_to_cart():
        assert True  # DISCOVERED: Cancellation works
    else:
        pytest.fail("DISCOVERED: Cancellation broken")
```

#### Business Rules Tests (Typical: 15-20 tests)

```python
@pytest.mark.business_rules
def test_card_format_validation():
    """PCI-DSS 6.5.3: Card Number Validation
    
    Discovers if system validates card number format.
    """
    fill_payment_form(card="abcd1234")  # Invalid format
    submit_payment()
    
    error = check_for_error()
    if error and "invalid" in error.lower():
        assert True  # DISCOVERED: Validates format
    else:
        log_violation(
            standard="PCI-DSS 4.0.1 Requirement 6.5.3",
            expected="Reject invalid card format",
            actual="Accepted 'abcd1234'",
            severity="HIGH"
        )
        pytest.fail("DISCOVERED: No card format validation")

@pytest.mark.business_rules
def test_expired_card_rejected():
    """Payment Industry Standard: Reject expired cards
    
    Discovers if system validates card expiration.
    """
    fill_payment_form(
        card="4111111111111111",
        expiry="01/2020"  # Expired
    )
    submit_payment()
    
    error = check_for_error()
    if error and "expired" in error.lower():
        assert True  # DISCOVERED: Validates expiration
    else:
        log_violation(
            standard="Payment Industry Best Practice",
            expected="Reject expired cards",
            actual="Accepted card expired in 2020",
            severity="HIGH"
        )
        pytest.fail("DISCOVERED: Accepts expired cards")

@pytest.mark.business_rules
def test_required_fields_validation():
    """ISO 25010: Required Field Validation
    
    Discovers if all required payment fields are validated.
    """
    submit_payment()  # Empty form
    
    error = check_for_error()
    if error and "required" in error.lower():
        assert True  # DISCOVERED: Validates required fields
    else:
        log_violation(
            standard="ISO 25010 - Functional Suitability",
            expected="Validate all required fields",
            actual="Accepted empty payment form",
            severity="MEDIUM"
        )
        pytest.fail("DISCOVERED: No required field validation")
```

---

### SHOPPING CART MODULE

#### Functional Tests (Typical: 8 tests)

```python
@pytest.mark.functional
def test_add_to_cart_works():
    """Discovers if add to cart functionality works"""
    add_to_cart(product_id=1)
    
    if item_in_cart(product_id=1):
        assert True  # DISCOVERED: Add to cart works
    else:
        pytest.fail("DISCOVERED: Add to cart broken")

@pytest.mark.functional
def test_cart_total_calculates():
    """Discovers if cart total calculates correctly"""
    add_to_cart(product_id=1, price=100)
    add_to_cart(product_id=2, price=50)
    
    total = get_cart_total()
    if total == 150:
        assert True  # DISCOVERED: Calculation correct
    else:
        pytest.fail(f"DISCOVERED: Wrong total ({total} != 150)")
```

#### Business Rules Tests (Typical: 12 tests)

```python
@pytest.mark.business_rules
def test_negative_quantity_rejected():
    """ISO 25010: Input Validation - Negative Values
    
    Discovers if system validates against negative quantities.
    """
    add_to_cart(product_id=1, quantity=-5)
    
    if item_in_cart_with_negative_quantity():
        log_violation(
            standard="ISO 25010 - Functional Suitability",
            expected="Reject negative quantities",
            actual="Accepted quantity=-5",
            severity="HIGH"
        )
        pytest.fail("DISCOVERED: Negative quantities accepted")
    else:
        assert True  # DISCOVERED: Validates quantities

@pytest.mark.business_rules
def test_quantity_maximum_enforced():
    """ISO 25010: Input Validation - Maximum Values
    
    Discovers if system enforces reasonable quantity limits.
    """
    add_to_cart(product_id=1, quantity=10000)
    
    cart_quantity = get_cart_item_quantity(product_id=1)
    if cart_quantity == 10000:
        log_violation(
            standard="ISO 25010 - Functional Suitability",
            expected="Enforce maximum quantity (e.g., 999)",
            actual="Accepted quantity=10000",
            severity="MEDIUM"
        )
        pytest.fail("DISCOVERED: No maximum quantity limit")
    else:
        assert True  # DISCOVERED: Maximum enforced
```

---

### SEARCH/FILTER MODULE

#### Functional Tests (Typical: 6 tests)

```python
@pytest.mark.functional
def test_search_returns_results():
    """Discovers if search returns relevant results"""
    results = search("laptop")
    
    if len(results) > 0:
        assert True  # DISCOVERED: Search works
    else:
        pytest.fail("DISCOVERED: Search returns no results")

@pytest.mark.functional
def test_filter_applies_correctly():
    """Discovers if filters apply correctly"""
    results = search_with_filter(category="electronics", price_max=500)
    
    if all(r.category == "electronics" and r.price <= 500 for r in results):
        assert True  # DISCOVERED: Filter works
    else:
        pytest.fail("DISCOVERED: Filter doesn't apply correctly")
```

#### Business Rules Tests (Typical: 10 tests)

```python
@pytest.mark.business_rules
@pytest.mark.parametrize("payload", ["' OR '1'='1", "' UNION SELECT"])
def test_sql_injection_in_search(payload):
    """OWASP ASVS 1.2.5: SQL Injection Prevention
    
    Discovers if SQL injection is possible in search.
    """
    results = search(payload)
    
    if "SQL" in str(results) or "error" in str(results).lower():
        log_violation(
            standard="OWASP ASVS v5.0-1.2.5",
            expected="Block SQL injection",
            actual=f"SQL error exposed with: {payload}",
            severity="CRITICAL"
        )
        pytest.fail("DISCOVERED: SQL Injection vulnerability")
    else:
        assert True  # DISCOVERED: SQL injection blocked

@pytest.mark.business_rules
@pytest.mark.parametrize("payload", ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"])
def test_xss_in_search_results(payload):
    """OWASP ASVS 1.2.1: XSS Prevention
    
    Discovers if XSS is possible in search results.
    """
    search(payload)
    
    if alert_triggered():
        log_violation(
            standard="OWASP ASVS v5.0-1.2.1",
            expected="Sanitize output, no script execution",
            actual=f"XSS payload executed: {payload}",
            severity="CRITICAL"
        )
        pytest.fail("DISCOVERED: XSS vulnerability")
    else:
        assert True  # DISCOVERED: XSS prevention works
```

---

### CONTACT FORM MODULE

#### Functional Tests (Typical: 4 tests)

```python
@pytest.mark.functional
def test_valid_submission_succeeds():
    """Discovers if valid form submission works"""
    submit_form(
        name="John Doe",
        email="john@example.com",
        message="Test message"
    )
    
    if confirmation_shown():
        assert True  # DISCOVERED: Submission works
    else:
        pytest.fail("DISCOVERED: Submission broken")
```

#### Business Rules Tests (Typical: 8 tests)

```python
@pytest.mark.business_rules
def test_email_format_validation():
    """RFC 5322: Email Format Validation
    
    Discovers if system validates email format.
    """
    submit_form(
        name="John",
        email="not-an-email",  # Invalid format
        message="Test"
    )
    
    error = check_for_error()
    if error and "email" in error.lower():
        assert True  # DISCOVERED: Validates email format
    else:
        log_violation(
            standard="RFC 5322 (Email Format)",
            expected="Reject invalid email format",
            actual="Accepted 'not-an-email'",
            severity="MEDIUM"
        )
        pytest.fail("DISCOVERED: No email validation")

@pytest.mark.business_rules
def test_message_length_limit():
    """ISO 25010: Input Length Validation
    
    Discovers if system enforces message length limit.
    """
    long_message = "a" * 10000
    submit_form(name="John", email="john@test.com", message=long_message)
    
    error = check_for_error()
    if error and "length" in error.lower():
        assert True  # DISCOVERED: Enforces limit
    else:
        log_violation(
            standard="ISO 25010 - Functional Suitability",
            expected="Enforce message length limit (e.g., 1000 chars)",
            actual=f"Accepted message of {len(long_message)} characters",
            severity="LOW"
        )
        pytest.fail("DISCOVERED: No length limit")
```

---

### USER PROFILE MODULE

#### Functional Tests (Typical: 6 tests)

```python
@pytest.mark.functional
def test_profile_view_works():
    """Discovers if profile viewing works"""
    login("user", "pass")
    profile = view_profile()
    
    if profile.contains_user_data():
        assert True  # DISCOVERED: Profile view works
    else:
        pytest.fail("DISCOVERED: Profile view broken")

@pytest.mark.functional
def test_profile_update_succeeds():
    """Discovers if profile update works"""
    login("user", "pass")
    update_profile(name="New Name", bio="New bio")
    
    updated_profile = view_profile()
    if updated_profile.name == "New Name":
        assert True  # DISCOVERED: Update works
    else:
        pytest.fail("DISCOVERED: Update doesn't persist")
```

#### Business Rules Tests (Typical: 10 tests)

```python
@pytest.mark.business_rules
@pytest.mark.parametrize("payload", ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"])
def test_xss_in_profile_fields(payload):
    """OWASP ASVS 1.2.1: XSS Prevention in Profile
    
    Discovers if XSS is possible in profile fields.
    """
    update_profile(bio=payload)
    view_profile()
    
    if alert_triggered():
        log_violation(
            standard="OWASP ASVS v5.0-1.2.1",
            expected="Sanitize profile input",
            actual=f"XSS executed in bio: {payload}",
            severity="HIGH"
        )
        pytest.fail("DISCOVERED: XSS in profile")
    else:
        assert True  # DISCOVERED: XSS prevention works

@pytest.mark.business_rules
def test_profile_access_control():
    """OWASP ASVS 4.1.1: Access Control
    
    Discovers if users can access other users' profiles without authorization.
    """
    login("user1", "pass1")
    user1_id = get_current_user_id()
    
    logout()
    login("user2", "pass2")
    
    # Try to access user1's profile edit page
    can_access = try_access_profile_edit(user1_id)
    
    if can_access:
        log_violation(
            standard="OWASP ASVS v5.0-4.1.1",
            expected="Deny access to other users' profiles",
            actual="User2 can edit User1's profile",
            severity="CRITICAL"
        )
        pytest.fail("DISCOVERED: Broken access control")
    else:
        assert True  # DISCOVERED: Access control works
```

---

## Key Takeaway: Universal Pattern

### Every Module Follows This Structure:

```python
"""
Module: test_[module].py

FUNCTIONAL TESTS (30-40% of tests):
- Happy path validation
- Core feature verification
- Integration flow testing
- Discovers if features WORK

BUSINESS RULES TESTS (60-70% of tests):
- Standards compliance validation
- Security requirement verification
- Accessibility testing
- Data quality validation
- Discovers if features meet STANDARDS
"""

# All tests follow: EXECUTE → OBSERVE → DECIDE
def test_feature():
    # EXECUTE: Perform action
    action()
    
    # OBSERVE: Capture result
    result = observe()
    
    # DECIDE: Compare to expected
    if result.is_correct():
        assert True
    else:
        pytest.fail("Issue discovered")
```

---

<a name="version-history"></a>
## 20. VERSION HISTORY

### Version 2.0 - November 2025 (Current - Universal Edition)

**Major Updates:**
- ✅ Complete DISCOVER vs ASSUME philosophy section with 4 detailed examples
- ✅ Anti-Patterns section (8 common mistakes to avoid)
- ✅ Comprehensive Pre-Development Questions (3 categories)
- ✅ Research Matrix by Module Type (8 module types with specific standards)
- ✅ Before Writing Code Checklist (15 validation points)
- ✅ Example Future Conversations (3 detailed scenarios)
- ✅ Common Patterns by Module (6 module types with code examples)
- ✅ Universal applicability (works across all domains)
- ✅ Extensive documentation (2,500+ lines)

**Philosophy Improvements:**
- Explicit DISCOVER formula: EXECUTE → OBSERVE → DECIDE
- Multiple examples showing right vs wrong approaches
- Clear anti-patterns with corrections
- Research matrix for any module type
- Reusable patterns across all industries

**Coverage:**
- Authentication/Login modules
- Payment/Financial modules
- Shopping Cart modules
- Search/Filter modules
- User Profile modules
- Contact Form modules
- Any web application module

### Version 1.0 - November 2025 (Deprecated)

**Initial Release:**
- Basic functional testing template
- Limited DISCOVER vs ASSUME explanation
- Generic code structure
- Basic standards references
- ~800 lines

**Limitations:**
- Examples too generic
- No detailed anti-patterns
- No example conversations
- No common patterns reference
- Limited module coverage

---

**End of Functional Template - Part 2**

**Integration Note:** These sections (18-20) should be read in conjunction with TEMPLATE_functional_business_rules_v2.md (Sections 1-17).

**Author:** Arévalo, Marc  
**Version:** 2.0 (Universal Edition)  
**Date:** November 2025

**Remember:** Tests discover behavior through execution, never assume outcomes.
