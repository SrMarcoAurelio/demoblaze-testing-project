# Test Plan - DemoBlaze E-commerce Testing Project

## 1. Introduction

This document outlines the testing strategy for DemoBlaze (https://www.demoblaze.com), a demo e-commerce application. The purpose of this project is to demonstrate manual and automated testing skills through comprehensive functional testing of core e-commerce features.

**Project Duration:** 2 weeks  
**Tester:** [Your Name]  
**Version:** 1.0  
**Date:** November 2024

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
- Security penetration testing
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
- Test user accounts (to be created during registration testing)
- Sample product selections from available inventory
- Test credit card data (demo values only)

---

## 6. Test Deliverables

The following artifacts will be produced:

1. **Documentation**
   - User Flows document (`docs/user-flows.md`)
   - Test Plan (`docs/test-plan.md`) - this document
   - Test Cases spreadsheet (`docs/test-cases.xlsx`)
   - Test Summary Report (`docs/test-summary-report.md`)

2. **Bug Reports**
   - Individual bug reports in `bug-reports/` directory
   - GitHub Issues for tracking
   - Screenshots/videos as evidence

3. **Automation Code**
   - Page Object classes (`pages/`)
   - Test scripts (`tests/`)
   - Configuration files (`pytest.ini`, `conftest.py`)
   - Requirements file (`requirements.txt`)

4. **Project Documentation**
   - README with setup instructions
   - Code comments and docstrings

---

## 7. Entry and Exit Criteria

### 7.1 Entry Criteria

Testing will begin when:
- ✅ Test environment is accessible (demoblaze.com is up)
- ✅ Testing tools are installed and configured
- ✅ User flows are documented
- ✅ Test cases are prepared
- ✅ GitHub repository is set up

### 7.2 Exit Criteria

Testing will be considered complete when:
- ✅ All planned test cases have been executed
- ✅ Minimum 15-20 test cases documented
- ✅ All critical and high-severity bugs are documented
- ✅ At least 5-8 automated tests are implemented
- ✅ Test summary report is completed
- ✅ Code coverage of critical flows reaches 80%+
- ✅ All deliverables are uploaded to GitHub

---

## 8. Test Schedule

| Phase | Activities | Duration | Status |
|-------|-----------|----------|--------|
| **Phase 1** | Setup & Planning | Day 1-2 | In Progress |
| - | Install tools, create repository | | |
| - | Document user flows | | |
| **Phase 2** | Manual Testing | Day 3-5 | Not Started |
| - | Create test cases | | |
| - | Execute manual tests | | |
| - | Document bugs | | |
| **Phase 3** | Test Automation | Day 6-10 | Not Started |
| - | Set up automation framework | | |
| - | Implement Page Object Model | | |
| - | Write automated tests | | |
| - | Execute and debug automation | | |
| **Phase 4** | Documentation | Day 11-12 | Not Started |
| - | Complete README | | |
| - | Test summary report | | |
| - | Code cleanup | | |
| **Phase 5** | Final Review | Day 13-14 | Not Started |
| - | Review all deliverables | | |
| - | Final commit to GitHub | | |
| - | Portfolio preparation | | |

---

## 9. Resources

### 9.1 Human Resources
- **QA Tester/Automation Engineer:** [Your Name]
- **Role:** Test planning, execution, automation, and reporting

### 9.2 Tools and Technologies
- **Test Management:** GitHub (issues, project board)
- **Documentation:** Markdown, Excel/Google Sheets
- **Automation:** Selenium WebDriver, Python, Pytest
- **Version Control:** Git, GitHub
- **Screenshots:** Built-in OS tools, browser DevTools

---

## 10. Risks and Mitigation

| Risk | Impact | Probability | Mitigation Strategy |
|------|--------|-------------|---------------------|
| Demo site goes down | High | Low | Document with screenshots, work offline on automation structure |
| Site contains intentional bugs | Medium | High | Document as findings, focus on demonstrating testing skills |
| Limited functionality | Low | High | Accept as constraint, focus on what exists |
| Browser compatibility issues | Medium | Low | Primarily test on Chrome, note Firefox differences |
| Time constraints | Medium | Medium | Prioritize critical flows, automate most important scenarios |
| Learning curve with tools | Medium | Medium | Follow documentation, use online resources |

---

## 11. Assumptions and Dependencies

### Assumptions
- DemoBlaze site will remain accessible throughout testing period
- Site functionality will not change during test execution
- Demo site bugs are intentional for learning purposes
- No access to backend/database for verification

### Dependencies
- Internet connection availability
- Browser compatibility with Selenium WebDriver
- Python and required libraries installation
- GitHub repository access

---

## 12. Test Metrics

The following metrics will be tracked:

- **Test Coverage:** % of user flows covered by test cases
- **Test Execution:** Total tests executed vs. planned
- **Pass/Fail Rate:** Percentage of tests passing
- **Defect Density:** Number of bugs found per module
- **Automation Coverage:** % of test cases automated
- **Defect Status:** Open vs. Documented bugs

**Target Metrics:**
- Test Coverage: 90%+
- Automation Coverage: 30%+ (critical paths)
- All critical flows tested

---

## 13. Approval

This test plan is created for portfolio demonstration purposes.

**Prepared by:** Arévalo, Marc
**Date:** November 2025
**Version:** 1.0

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Nov 2024 | Arévalo, Marc | Initial test plan creation |