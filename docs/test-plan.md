# Test Plan - DemoBlaze E-commerce Testing Project

## 1. Introduction

This document outlines the testing strategy for DemoBlaze (https://www.demoblaze.com), a demo e-commerce application. The purpose of this project is to demonstrate manual and automated testing skills through comprehensive functional testing of core e-commerce features.

**Project Duration:** 2 weeks  
**Tester:** Marc Arévalo  
**Version:** 2.0 (Updated after Phase 2 completion)  
**Date:** November 2025  
**Last Updated:** November 5, 2025

---

## 2. Test Objectives

- **Primary:** Validate all core functionalities work as expected
- **Secondary:** Identify bugs, usability issues, and improvement opportunities
- **Portfolio Goal:** Demonstrate QA testing skills through thorough documentation and automation
- Ensure critical user paths (registration, login, purchase) function correctly
- Verify cart operations and product management work properly
- Document any defects found with detailed bug reports
- Create reusable automated test scripts for regression testing

---

## 3. Scope

### 3.1 In Scope

The following features will be tested:

- **User Management**
  - User registration (Sign up)
  - User login/logout
  - Session management

- **Product Browsing**
  - Homepage product display
  - Category filtering (Phones, Laptops, Monitors)
  - Product details view
  - Product pagination (Next/Previous)

- **Shopping Cart**
  - Add products to cart
  - Remove products from cart
  - Cart total calculation
  - Multiple products in cart

- **Purchase Flow**
  - Guest user checkout
  - Registered user checkout
  - Order form validation
  - Purchase confirmation

- **Contact Form**
  - Form submission
  - Field validation

### 3.2 Out of Scope

The following are NOT included in this testing cycle:

- Backend/database testing
- API testing (may be added in future iterations)
- Payment gateway integration (demo site only)
- Performance and load testing
- Advanced security penetration testing (CORS, Prototype Pollution)
- Mobile responsiveness (desktop focus)
- Accessibility testing (WCAG compliance)
- Integration with third-party services

---

## 4. Test Approach and Strategy

### 4.1 Testing Types

**Phase 1: Manual Testing (Week 1)**
- Exploratory testing to understand application behavior
- Functional testing based on defined user flows
- Negative testing (invalid inputs, boundary cases)
- Usability testing (user experience evaluation)
- Basic security testing (SQL Injection, XSS, username enumeration)

**Phase 2: Test Automation (Week 2)**
- Automate critical paths using Selenium WebDriver + Python
- Implement Page Object Model (POM) design pattern
- Focus on regression testing for repetitive scenarios
- Minimum 5-8 automated test scripts

### 4.2 Test Design Techniques

- **Equivalence Partitioning:** Group similar inputs (valid/invalid credentials)
- **Boundary Value Analysis:** Test limits (empty cart, maximum products)
- **Decision Table Testing:** Login combinations (valid user + valid password, etc.)
- **Error Guessing:** Based on common e-commerce issues (spam clicking, cart bugs)

### 4.3 Test Execution Approach

1. Execute all manual test cases and document results
2. Report bugs immediately upon discovery
3. Re-test fixed bugs (if applicable)
4. Automate stable and critical test scenarios
5. Run automated tests to verify regression

---

## 5. Test Environment

### 5.1 Application Under Test
- **URL:** https://www.demoblaze.com
- **Type:** Demo e-commerce web application
- **Environment:** Production (public demo)

### 5.2 Test Infrastructure
- **Operating System:** Windows 11
- **Browsers:** 
  - Primary: Google Chrome (latest version)
  - Secondary: Mozilla Firefox (latest version)
- **Automation Tools:**
  - Python 3.11+
  - Selenium WebDriver 4.x
  - Pytest framework
- **Version Control:** Git + GitHub
- **IDE:** Visual Studio Code

### 5.3 Test Data
- Test user accounts (created during registration testing)
- Sample product selections from available inventory
- Test credit card data (demo values only)

---

## 6. Test Deliverables

The following artifacts will be produced:

1. **Documentation**
   - User Flows document (`docs/users-flow.md`) ✅ Complete
   - Test Plan (`docs/test-plan.md`) - this document ✅ Complete
   - Test Cases spreadsheet (`docs/DemoBlaze_Test_Cases.xlsx`) ✅ Complete (36 test cases)
   - Test Summary Report (`docs/Test_Summary_Report.md`) ✅ Complete

2. **Bug Reports**
   - GitHub Issues for tracking ✅ Complete (29 bugs documented)
   - Screenshots/evidence included ✅ Complete

3. **Automation Code** (Phase 3 - In Progress)
   - Page Object classes (`pages/`) ⏳ Pending
   - Test scripts (`tests/`) ⏳ Pending
   - Configuration files (`pytest.ini`, `conftest.py`) ⏳ Pending
   - Requirements file (`requirements.txt`) ⏳ Pending

4. **Project Documentation**
   - README with setup instructions ✅ Complete
   - Code comments and docstrings ⏳ Pending

---

## 7. Entry and Exit Criteria

### 7.1 Entry Criteria

Testing will begin when:
- ✅ Test environment is accessible (demoblaze.com is up)
- ✅ Testing tools are installed and configured
- ✅ User flows are documented
- ✅ Test cases are prepared
- ✅ GitHub repository is set up

**Status:** ✅ All entry criteria met

### 7.2 Exit Criteria

Testing will be considered complete when:
- ✅ All planned test cases have been executed (36/36 executed)
- ✅ Minimum 15-20 test cases documented (36 documented - target exceeded)
- ✅ All critical and high-severity bugs are documented (5 critical, 10 high documented)
- ⏳ At least 5-8 automated tests are implemented (Phase 3 - pending)
- ✅ Test summary report is completed
- ⏳ Code coverage of critical flows reaches 80%+ (Phase 3 - pending)
- ⏳ All deliverables are uploaded to GitHub (Phase 3 automation pending)

**Phase 2 Status:** ✅ All Phase 2 exit criteria met

---

## 8. Test Schedule

| Phase | Activities | Duration | Status |
|-------|-----------|----------|--------|
| **Phase 1** | **Setup & Planning** | Day 1-2 | ✅ **COMPLETED** |
| - | Install tools, create repository | | ✅ Done |
| - | Document user flows | | ✅ Done |
| **Phase 2** | **Manual Testing** | Day 3-5 | ✅ **COMPLETED** |
| - | Create test cases (36 total) | | ✅ Done |
| - | Execute manual tests | | ✅ Done |
| - | Document bugs (29 found) | | ✅ Done |
| **Phase 3** | **Test Automation** | Day 6-10 | 🔄 **IN PROGRESS** |
| - | Set up automation framework | | ⏳ Starting |
| - | Implement Page Object Model | | ⏳ Pending |
| - | Write automated tests | | ⏳ Pending |
| - | Execute and debug automation | | ⏳ Pending |
| **Phase 4** | **Documentation** | Day 11-12 | ⏳ Pending |
| - | Complete README | | ✅ Done |
| - | Test summary report | | ✅ Done |
| - | Code cleanup | | ⏳ Pending |
| **Phase 5** | **Final Review** | Day 13-14 | ⏳ Pending |
| - | Review all deliverables | | ⏳ Pending |
| - | Final commit to GitHub | | ⏳ Pending |
| - | Portfolio preparation | | ⏳ Pending |

---

## 9. Resources

### 9.1 Human Resources
- **QA Tester/Automation Engineer:** Marc Arévalo
- **Role:** Test planning, execution, automation, and reporting

### 9.2 Tools and Technologies
- **Test Management:** GitHub (issues, project board)
- **Documentation:** Markdown, Excel/Google Sheets
- **Automation:** Selenium WebDriver, Python, Pytest
- **Version Control:** Git, GitHub
- **Screenshots:** Built-in OS tools, browser DevTools

---

## 10. Risks and Mitigation

| Risk | Impact | Probability | Status | Mitigation Strategy |
|------|--------|-------------|--------|---------------------|
| Demo site goes down | High | Low | ✅ Mitigated | Documentation complete with screenshots |
| Site contains intentional bugs | Medium | High | ✅ Accepted | Documented 29 bugs, excellent for portfolio |
| Limited functionality | Low | High | ✅ Accepted | Focus on available features completed |
| Browser compatibility issues | Medium | Low | ✅ Managed | Primary testing on Chrome completed |
| Time constraints | Medium | Medium | ✅ Managed | Phase 2 completed successfully |
| Learning curve with tools | Medium | Medium | ✅ Overcome | Manual testing skills demonstrated |

---

## 11. Assumptions and Dependencies

### Assumptions
- DemoBlaze site will remain accessible throughout testing period ✅
- Site functionality will not change during test execution ✅
- Demo site bugs are intentional for learning purposes ✅
- No access to backend/database for verification ✅

### Dependencies
- Internet connection availability ✅
- Browser compatibility with Selenium WebDriver ⏳ (Phase 3)
- Python and required libraries installation ⏳ (Phase 3)
- GitHub repository access ✅

---

## 12. Test Metrics

### 12.1 Phase 2 - Manual Testing Results

**Test Execution Metrics:**
- **Total Test Cases Planned:** 15-20
- **Total Test Cases Created:** 36  (exceeded target)
- **Test Cases Executed:** 36 (100%)
- **Test Cases Passed:** 7 (19.4%)
- **Test Cases Failed:** 29 (80.6%)

**Defect Metrics:**
- **Total Bugs Found:** 29
- **Critical:** 5 (17.2%)
- **High:** 10 (34.5%)
- **Medium:** 10 (34.5%)
- **Low:** 4 (13.8%)
- **Defect Density:** 0.81 bugs per test case

**Coverage Metrics:**
- **Module Coverage:** 100% (all modules tested)
- **Requirements Coverage:** 90%+ 
- **Test Coverage Target:** 90%+  Achieved

**Target Metrics Status:**
-  Test Coverage: 90%+ (Met)
-  Automation Coverage: 30%+ (Phase 3 pending)
-  All critical flows tested (Met)

### 12.2 Bugs by Module

| Module | Total Bugs | Critical | High | Medium | Low |
|--------|------------|----------|------|--------|-----|
| Authentication | 5 | 3 | 2 | 0 | 0 |
| Cart | 6 | 2 | 0 | 2 | 2 |
| Checkout | 5 | 1 | 2 | 0 | 2 |
| Browse/Products | 6 | 0 | 2 | 3 | 1 |
| Contact | 5 | 0 | 3 | 2 | 0 |
| Global/UI | 2 | 0 | 1 | 3 | 0 |

### 12.3 Top 5 Critical Bugs

1. **Issue #9:** System allows purchase with empty cart
2. **Issue #13:** SQL Injection vulnerability
3. **Issue #18:** No rate limiting on login attempts
4. **Issue #17:** Login error reveals valid usernames
5. **Issue #4:** No credit card validation

---

## 13. Key Findings and Observations

### 13.1 Security Vulnerabilities
-  **SQL Injection** possible in username field
-  **No rate limiting** on login attempts (brute-force risk)
-  **Username enumeration** via different error messages
-  **Weak passwords accepted** (single character passwords allowed)
-  **No credit card validation**

### 13.2 Business Logic Issues
-  Empty cart purchases allowed
-  No authentication verification during checkout
-  Missing email field in checkout form

### 13.3 Usability Issues
- JavaScript alerts instead of modern modals
- No visual feedback on category selection
- Missing search functionality
- Product images not clickable after pagination
- No loading indicators

### 13.4 Missing Features
- Order tracking and cancellation
- Invoice download and order history
- "Clear Cart" functionality
- Email validation in contact form
- Rate limiting on contact form submissions

---

## 14. Recommendations

### High Priority (Critical for Production):
1. Fix all critical security vulnerabilities immediately
2. Implement proper input validation across all forms
3. Add rate limiting to prevent brute-force attacks
4. Implement password complexity requirements
5. Add proper business logic validation (empty cart, etc.)

### Medium Priority:
6. Add loading indicators for better UX
7. Implement search functionality
8. Fix pagination bugs
9. Add currency symbols to prices
10. Make footer links functional

### Low Priority (Enhancement):
11. Replace JavaScript alerts with custom modals
12. Add "Clear Cart" button
13. Improve product descriptions
14. Create custom 404 page
15. Update copyright year

---

## 15. Approval

This test plan is created for portfolio demonstration purposes.

**Prepared by:** Arévalo, Marc  
**Date:** November 2025  
**Version:** 2.0  
**Phase 2 Status:**  Complete  
**Ready for Phase 3:**  Yes

---

## 16. Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Nov 2024 | Arévalo, Marc | Initial test plan creation |
| 2.0 | Nov 5, 2025 | Arévalo, Marc | Updated with Phase 2 results: 36 test cases executed, 29 bugs found. Added metrics, findings, and recommendations. Ready for Phase 3. |
