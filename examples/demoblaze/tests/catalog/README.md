# 📂 Catalog Module - Test Suite Documentation

## 📋 Overview

Complete test coverage for DemoBlaze's **Catalog/Home Page** functionality, migrated to **Page Object Model (POM)** architecture following the **DISCOVER philosophy**.

**Philosophy:** EXECUTE → OBSERVE → DECIDE (No assumptions, only real discoveries)

---

## 📊 Test Coverage Summary

| Test File | Tests | Executions | Purpose |
|-----------|-------|------------|---------|
| **test_catalog_functional.py** | 30 | ~30 | Category navigation, product display, pagination, business rules |
| **test_catalog_security.py** | 16 | ~30 | SQL injection, XSS, IDOR, timing attacks, session security |
| **TOTAL** | **46** | **~60** | **Complete Catalog coverage** |

---

## 🏗️ Architecture

### Page Object Model

**`pages/catalog_page.py`** (710 lines)
- Category navigation (Phones, Laptops, Monitors, Home)
- Product listing (names, prices, images, links)
- Pagination (next, previous, boundary conditions)
- Product interaction (click, navigate to details)
- Validation methods (completeness, format, broken links)
- Performance measurement (load time, category switch time)
- Accessibility testing (keyboard navigation, ARIA labels, focus indicators)
- Security testing helpers (SQL errors, directory listing, verbose errors)

### Test Organization

```
tests_new/catalog/
├── __init__.py
├── test_catalog_functional.py    # Core features + business rules
├── test_catalog_security.py      # Security exploits
└── README.md                      # This file
```

---

## 📝 Standards Tested

- **ISO 25010** - Software Quality (Completeness, Consistency, Reliability, Performance)
- **WCAG 2.1 Level A & AA** - Web Content Accessibility Guidelines
- **OWASP ASVS v5.0** - Application Security Verification
- **CWE** - Common Weakness Enumeration (CWE-89, CWE-79, CWE-22, CWE-639, etc.)
- **CVSS 3.1** - Vulnerability Scoring (9.8 CRITICAL → 5.3 MEDIUM)

---

## 🚀 Running the Tests

### Run All Catalog Tests
```bash
pytest tests_new/catalog/ -v
```

### Run by File
```bash
# Functional tests only
pytest tests_new/catalog/test_catalog_functional.py -v

# Security tests only
pytest tests_new/catalog/test_catalog_security.py -v
```

### Run by Priority
```bash
# Critical tests
pytest tests_new/catalog/ -m critical -v

# Business rules
pytest tests_new/catalog/ -m business_rules -v

# Security tests
pytest tests_new/catalog/ -m security -v

# Accessibility tests
pytest tests_new/catalog/ -m accessibility -v
```

### Run Specific Tests
```bash
# Category navigation tests
pytest tests_new/catalog/ -k "category" -v

# Pagination tests
pytest tests_new/catalog/ -k "pagination" -v

# SQL injection tests
pytest tests_new/catalog/ -k "sql_injection" -v

# XSS tests
pytest tests_new/catalog/ -k "xss" -v
```

---

## 📈 Test Categories

### Functional Tests (30)

**Category Navigation (5 tests):**
- Navigate to Phones, Laptops, Monitors categories
- Home button shows all products
- Category switching works correctly

**Product Display (5 tests):**
- Products display after page load
- Product names, prices, images visible
- Product links functional

**Pagination (3 tests):**
- Next button functionality
- Previous button functionality
- Boundary conditions

**Navigation (3 tests):**
- Click product navigates to details
- Product URL changes correctly
- Browser back button returns to catalog

**Business Rules (15 tests):**
- All products have name/price/description (BR-001 to BR-003)
- All images valid and load successfully (BR-004)
- Price format consistency (BR-005)
- Product links not broken (BR-006)
- Performance: load time, category switch time (BR-007, BR-008)
- Pagination requirements (BR-009)
- Empty categories not allowed (BR-010)
- Category active state indication (BR-011)
- **Accessibility:**
  - Product images have alt text (BR-012)
  - Keyboard navigation categories (BR-013)
  - Category links have ARIA labels (BR-014)
  - Focus indicators visible (BR-015)

### Security Tests (16)

**Injection Attacks (7 tests):**
- SQL injection in category filter (5 payloads)
- SQL injection in product ID (3 payloads)
- XSS in product search (4 payloads)
- Stored XSS in product reviews

**IDOR (2 tests):**
- Product access enumeration
- Invalid product ID handling

**Path Traversal (1 test):**
- Product images path traversal (4 payloads)

**Other Security (6 tests):**
- Product enumeration
- Timing attack on product existence
- Session fixation catalog browsing
- Cookie security flags
- CSRF token catalog actions
- Security headers validation
- Rate limiting catalog browsing
- Verbose error messages
- Directory listing exposure

---

## 🔍 Key Features

### DISCOVER Philosophy Examples

**Category Navigation:**
```python
# EXECUTE: Navigate to category
catalog.click_laptops_category()

# OBSERVE: Check products displayed
laptops_count = catalog.get_product_count()

# DECIDE: Category should show products
assert laptops_count > 0, "Laptops category is empty"
```

**SQL Injection Testing:**
```python
# EXECUTE: Attempt SQL injection
malicious_url = f"{base_url}?cat=' OR '1'='1"
browser.get(malicious_url)

# OBSERVE: Check for SQL errors
has_error, indicators = catalog.check_for_sql_error_indicators()

# DECIDE: Should not disclose errors
if has_error:
    pytest.fail(f"DISCOVERED: SQL error disclosure")
```

**Accessibility Validation:**
```python
# EXECUTE: Test keyboard navigation
results = catalog.test_keyboard_navigation_categories()

# OBSERVE: Check navigation works
tab_works = results['tab_navigation_works']

# DECIDE: Keyboard navigation required
if not tab_works:
    logger.warning("⚠ ACCESSIBILITY ISSUE")
```

---

## 🎯 Vulnerability Discovery Metrics

### High-Risk Vulnerabilities Tested

1. **SQL Injection** (CVSS 9.8 CRITICAL) - Category filter, product ID
2. **XSS Attacks** (CVSS 8.2 HIGH) - Search, reviews
3. **Path Traversal** (CVSS 7.5 HIGH) - File system access
4. **IDOR** (CVSS 7.5 HIGH) - Product enumeration
5. **Session Fixation** (CVSS 6.5 MEDIUM) - Session security
6. **Information Disclosure** (CVSS 5.3 MEDIUM) - Verbose errors, directory listing

---

## 👨‍💻 Author

**Marc Arévalo**
Version: 1.0
Date: 2025

**Philosophy:** DISCOVER (EXECUTE → OBSERVE → DECIDE)
*"Tests should discover reality, not assume it."*

---

## 📝 Changelog

### Version 1.0 (Initial Release)
- ✅ 46 tests migrated to POM architecture
- ✅ 100% parity with original test suite
- ✅ DISCOVER philosophy implemented
- ✅ Comprehensive standards coverage
- ✅ Real exploitation attempts (no mocking)
