# DemoBlaze QA Testing Project

**Learning Journey: From Manual Testing to Test Automation**

**Author**: Marc Arévalo  
**Duration**: 20 days (November 2025)  
**Status**: Active Development - Phase 3 (Automation) - 75% Complete

---

## Transparency Statement

This repository documents my complete learning journey into QA Testing, starting from zero knowledge. It represents 20 days of intensive work including:

- Manual testing and bug discovery
- Learning Python and Selenium from scratch
- Multiple code iterations and improvements
- Extensive AI collaboration (Claude AI & Gemini) for learning and code review
- Creating reusable testing templates and documentation

**About AI Usage**: This project was built with significant AI assistance. AI helped me:
- Understand QA fundamentals and best practices
- Learn Python, Selenium, and Pytest
- Review and improve code through multiple iterations
- Debug test failures and improve test design
- Write comprehensive documentation

**What I did myself**:
- Executed all 36 manual test cases
- Discovered all 29 bugs through hands-on testing
- Made technical decisions about what to test and how
- Reviewed, understood, and tested every line of AI-generated code
- Rejected and requested improvements when code didn't meet standards
- Created the project structure and testing strategy

This README is completely transparent about the process, including mistakes, iterations, and what remains incomplete.

---

## Personal Message from the Author

It's a genuine pleasure to share this repository with the community. If you've made it this far and find something useful—whether for learning or your own projects—it genuinely makes me happy. I've tried to document EVERYTHING: each test has its own README explaining how it works, I update the code daily to meet current standards, and although there's still plenty of work left to finish it, this project has all my time and attention right now.

If you have questions, use GitHub Discussions or email me directly. If you have QA experience and like the project, or simply want to help make it more useful for more people, I'd be delighted to collaborate with you. The idea is that this actually helps someone learning, not just becoming another project on GitHub.

---

## How to Use This Repository

This repository can be used in two ways depending on your needs:

**Option 1 - Direct Implementation**: Take the existing test files (`tests/` directory), modify the configuration variables (BASE_URL, locators, test data), and run them against your application. Each test file includes a comprehensive README explaining how everything works.

**Option 2 - Template-Based Development**: Use the testing templates (`templates/` directory - 4,000+ lines) as a foundation to create AI-assisted test generation. The templates include complete methodology (DISCOVER vs ASSUME philosophy), code patterns, standards references (OWASP, ISO 25010, PCI-DSS), and example conversations for creating new test modules. Perfect for building an AI agent that generates and corrects test code following professional standards.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Current Status](#current-status)
3. [The 20-Day Journey](#the-20-day-journey)
4. [Technical Architecture](#technical-architecture)
5. [Testing Philosophy](#testing-philosophy)
6. [Module Breakdown](#module-breakdown)
7. [Code Quality Journey](#code-quality-journey)
8. [Repository Structure](#repository-structure)
9. [Installation & Usage](#installation--usage)
10. [Key Learnings](#key-learnings)
11. [What's Next](#whats-next)
12. [For Recruiters](#for-recruiters)
13. [Acknowledgments](#acknowledgments)

---

## Project Overview

### The Goal

Learn QA Testing by building a real testing project from scratch, documenting every step, mistake, and improvement along the way.

### The Application Under Test

**DemoBlaze** (https://www.demoblaze.com) - A demo e-commerce website designed for testing practice. It intentionally contains bugs, making it perfect for learning bug detection and test automation.

### By The Numbers

**Code & Documentation**:
- 3,390 lines of Python test code
- 13,255 lines of Markdown documentation
- 119 automated tests
- 4 comprehensive testing templates
- 20+ README files (module-specific documentation)

**Testing Coverage**:
- 36 manual test cases created and executed
- 29 bugs discovered and documented
- 3 test modules fully automated (Login, Purchase, Signup)
- 2 types of tests per module: Functional + Security

**Time Investment**:
- 20 days total duration
- Phase 1 (Planning): 2 days
- Phase 2 (Manual Testing): 6 days
- Phase 3 (Automation): 12 days (ongoing)
- Estimated 100+ hours of active work

---

## Current Status

### Completed ✅

**Phase 1: Planning & Documentation**
- ✅ Test strategy and planning
- ✅ User flows documentation (10 scenarios)
- ✅ Test plan with scope and approach
- ✅ 36 test cases in Excel format
- ✅ Repository structure and Git setup

**Phase 2: Manual Testing**
- ✅ Executed all 36 test cases
- ✅ Discovered 29 bugs (5 critical, 10 high, 10 medium, 4 low)
- ✅ GitHub Issues for bug tracking
- ✅ Test summary report
- ✅ Bug severity classification

**Phase 3: Test Automation (In Progress)**
- ✅ Selenium + Pytest framework setup
- ✅ Login module: 33 tests (v3.1 - final)
- ✅ Purchase module: 56 tests split into:
  - Functional tests: 28 tests
  - Security tests: 28 tests
- ✅ Signup module: 30 tests
- ✅ Cross-browser support (Chrome, Firefox, Edge)
- ✅ HTML report generation
- ✅ Template system for future modules

### In Progress 🔄

- Login module needs restructuring (currently 1 file, should be 2 like Purchase)
- Conftest.py needs updating for new fixture patterns
- E2E (End-to-End) flow tests
- Additional test modules (Catalog, Contact, About)

### Not Started ❌

- Page Object Model (POM) refactoring
- CI/CD pipeline (GitHub Actions)
- API testing layer
- Performance testing
- Visual regression testing

---

## The 20-Day Journey

### Week 1: Foundations (Days 1-7)

**Days 1-2: Understanding QA** (~10 hours)
- Researched QA fundamentals: what is testing, why it matters
- Learned about test plans, test cases, bug reports
- Chose DemoBlaze as practice application
- Created project roadmap and Git repository
- Wrote comprehensive test plan

**Key Milestone**: First test plan written, understanding of QA process established

**Days 3-5: Manual Testing** (~20 hours)
- Created 10 user flow scenarios
- Designed 36 detailed test cases in Excel
- Learned test case structure: ID, steps, expected results, actual results
- Understood test data management
- Started executing test cases

**Key Milestone**: Complete test case suite ready for execution

**Days 6-7: Bug Discovery** (~15 hours)
- Executed all 36 test cases systematically
- Discovered first critical bug: empty cart purchase allowed
- Found 29 total bugs including security vulnerabilities
- Learned GitHub Issues for bug tracking
- Created test summary report

**Key Milestone**: 29 bugs documented, 80.6% failure rate discovered

### Week 2: First Steps in Automation (Days 8-14)

**Days 8-9: Setup & First Script** (~12 hours)
- Installed Python 3.11, pip, VS Code
- Installed Selenium, Pytest, webdriver-manager
- Created first test: `test_login_valid_credentials`
- Learned about WebDriver, locators (ID, XPath, CSS)
- Understood fixtures and conftest.py setup
- Struggled with element not found errors (learned WebDriverWait)

**Key Milestone**: First automated test passing

**Days 10-12: Login Module Development** (~18 hours)
- **Version 1.0**: Basic 6 tests (valid login, invalid password, etc.)
- Feedback: "Need security tests"
- **Version 2.0**: Added SQL Injection and XSS tests (19 total)
- Feedback: "Tests should be parametrized for better reporting"
- **Version 3.0**: Parametrized security tests
- Feedback: "Need cross-browser support"
- **Version 3.1**: Cross-browser testing, improved logging (33 tests final)

**Key Conversations**:
- "Why isn't my test finding the element?" → Learned explicit waits
- "How to test multiple SQL injection payloads efficiently?" → Learned @pytest.mark.parametrize
- "Tests pass but miss edge cases" → Learned boundary testing
- "Code has repetition" → Created helper functions

**Key Milestone**: 33 comprehensive tests with security coverage

**Days 13-14: Understanding Standards** (~10 hours)
- Learned about OWASP Top 10
- Understood ISO 25010 software quality standards
- Learned PCI-DSS for payment security
- Critical realization: **Tests should DISCOVER behavior, not ASSUME it**

**Key Milestone**: Shifted from "testing what should work" to "discovering what actually works"

### Week 3: Scaling & Templates (Days 15-20)

**Days 15-17: Purchase Module** (~20 hours)
- Realized Login approach (1 file) doesn't scale well
- **New structure**: Separate functional and security tests
- Created `test_purchase.py`: 28 functional tests
- Created `test_purchase_security.py`: 28 security tests
- Each test cites standards (OWASP ASVS, PCI-DSS, ISO 25010)
- Tests **discover** violations objectively

**Key Conversations**:
- "How to organize tests as project grows?" → Learned separation of concerns
- "Why separate functional and security?" → Better organization and reporting
- "How to make code reusable for other projects?" → Created template system

**Key Milestone**: Scalable test structure established

**Days 18-19: Template System** (~15 hours)
- Created comprehensive testing templates:
  - `functional_template_complete_guide.md` (544 lines)
  - `template_functional_business_rules_v2.md` (detailed implementation)
  - `Security_template_complete_guide.md`
  - `Template_security_exploitation_part1.md`
- Templates document the **DISCOVER vs ASSUME** philosophy
- Reusable for any web application, not just DemoBlaze

**Key Milestone**: Reusable framework for future testing projects

**Day 20: Signup Module & Documentation** (~12 hours)
- Applied template to create signup tests: 30 tests
- Comprehensive documentation for all modules
- Realized Login needs refactoring to match Purchase structure
- Started this README

**Key Milestone**: 119 tests total, professional documentation

---

## Technical Architecture

### Technology Stack

```
Python 3.11+
├── Selenium 4.25.0              # Browser automation
├── Pytest 8.3.3                 # Test framework
├── pytest-html 4.1.1            # HTML reports
└── webdriver-manager 4.0.2      # Automatic driver management
```

### Testing Framework

**Design Pattern**: Functional programming with helper functions (POM planned for future)

**Key Components**:
- **conftest.py**: Global pytest configuration and fixtures
- **Helper functions**: Reusable utilities per module
- **Fixtures**: Browser setup, page navigation
- **Parametrized tests**: Testing multiple inputs efficiently
- **Markers**: Categorizing tests (functional, business_rules, xfail)

### Cross-Browser Support

Tests run on:
- Google Chrome (primary)
- Mozilla Firefox
- Microsoft Edge

Command: `pytest tests/login/ --browser=firefox`

### Reporting

**HTML Reports**: Automatically generated via pytest-html
- Organized by module (login/, purchase/, signup/)
- Timestamped filenames
- Browser name in filename
- Self-contained (includes CSS/JS)

Location: `test_results/{module}/report_{browser}_{timestamp}.html`

---

## Testing Philosophy

### Core Principle: DISCOVER vs ASSUME

**The Foundation**: Tests should **discover** how the application actually behaves, not **assume** how it should behave.

**Wrong Approach (ASSUME)**:
```python
def test_empty_form_rejected():
    """This test ASSUMES DemoBlaze validates forms"""
    submit_form(empty_data)
    # Assumes validation exists
    assert validation_error_shown()  # Will fail on DemoBlaze
```

**Correct Approach (DISCOVER)**:
```python
def test_empty_form_behavior():
    """ISO 25010: Forms should validate required fields.
    
    This test DISCOVERS whether validation exists.
    """
    submit_form(empty_data)
    response = observe_response()
    
    if validation_error_shown():
        assert True  # DISCOVERED: Validation works
    else:
        log_violation("ISO 25010 - Missing validation")
        pytest.fail("DISCOVERED: No validation")
```

### Two Test Categories

**1. Functional Tests (Happy Path)**
- Purpose: Verify features work with valid inputs
- Mark: `@pytest.mark.functional`
- Expected: Should pass (discovers working features)
- Example: `test_valid_login`, `test_add_to_cart`

**2. Business Rules Tests (Standards Compliance)**
- Purpose: Verify compliance with industry standards
- Mark: `@pytest.mark.business_rules` + `@pytest.mark.xfail`
- Expected: Should fail on DemoBlaze (discovers violations)
- Cites specific standards: OWASP ASVS 5.0, ISO 25010, PCI-DSS
- Example: `test_credit_card_validation`, `test_sql_injection_prevention`

### Standards Referenced

All business rules tests cite specific standards:

- **OWASP ASVS 5.0**: Authentication, session management, input validation
- **OWASP Top 10 2021**: Common security risks
- **ISO 25010**: Software quality model
- **PCI-DSS 4.0.1**: Payment card security
- **NIST 800-63B**: Digital identity guidelines
- **WCAG 2.1 Level AA**: Accessibility standards

---

## Module Breakdown

### Login & Authentication (33 tests)

**Status**: ✅ Complete (needs restructuring)  
**File**: `tests/login/test_dem_login.py` (currently 1 file)  
**Version**: 3.1  
**Documentation**: `tests/login/README.md` (1,422 lines)

**Test Distribution**:
- Basic authentication: 6 tests
- SQL Injection: 7 parametrized tests
- XSS: 4 parametrized tests
- Input validation: 2 tests
- Boundary tests: 4 tests
- Advanced security: 2 tests
- Known vulnerabilities: 3 tests (xfail)
- UI interaction: 2 tests
- Cross-browser: All tests

**Key Features**:
- Cross-browser support (Chrome, Firefox, Edge)
- Real-time logging
- Comprehensive security coverage
- Parametrized tests for better reporting

**Note**: Currently structured as single file. Should be refactored to match Purchase structure:
- `tests/login/functional-tests/test_login.py`
- `tests/login/security-tests/test_login_security.py`

### Purchase & Cart (56 tests)

**Status**: ✅ Complete  
**Structure**: Split into functional and security (correct structure)  
**Version**: 4.0  
**Documentation**: 2 comprehensive READMEs (1,428 + 1,400 lines)

**Functional Tests** (`tests/purchase/functional-tests/test_purchase.py`): 28 tests
- Purchase flow: 11 tests
- Cart operations: 10 tests
- UI/Navigation: 8 tests
- Business rules: 10 tests (xfail)
- Parametrized validation: 12 scenarios

**Security Tests** (`tests/purchase/security-tests/test_purchase_security.py`): 28 tests
- Authentication bypass: 5 tests
- SQL Injection: 2 tests
- XSS: 2 tests
- Business logic: 6 tests
- Data validation: 3 tests
- Bot protection: 5 tests
- PCI-DSS compliance: 4 tests
- Accessibility: 3 tests

**Key Features**:
- Proper separation of concerns
- Each test cites specific standards
- Tests DISCOVER violations objectively
- Comprehensive documentation per file
- Template for future modules

### Signup & Registration (30 tests)

**Status**: ✅ Complete  
**File**: `tests/signup/test_signup.py`  
**Documentation**: `tests/signup/README_signup.md`

**Test Distribution**:
- Valid registrations: 5 tests (numbers, special chars, unicode, emojis)
- Invalid scenarios: 2 tests (existing user, empty fields)
- Security tests: 7 tests (SQL injection, XSS)
- Boundary testing: 5 tests (weak passwords, long inputs)
- Edge cases: 8 tests (spaces, case sensitivity)
- Integration: 3 tests (signup → login)

**Key Features**:
- Class-based structure (`TestSignup`)
- Helper methods for DRY code
- Unicode and emoji testing
- Integration test with login

### Templates (4 comprehensive guides)

**Status**: ✅ Complete  
**Total Documentation**: 4,000+ lines

**Functional Testing Templates**:
1. `functional_template_complete_guide.md` (544 lines)
   - Complete philosophy and methodology
   - DISCOVER vs ASSUME examples
   - Usage scenarios
   
2. `template_functional_business_rules_v2.md`
   - Implementation guide
   - Code structure
   - Standards reference

**Security Testing Templates**:
3. `Security_template_complete_guide.md`
   - Security testing methodology
   - OWASP Top 10 coverage
   - Exploitation techniques
   
4. `Template_security_exploitation_part1.md`
   - Detailed security test examples
   - Standard citations
   - Real-world scenarios

**Purpose**: Reusable framework for testing any web application, not just DemoBlaze.

---

## Code Quality Journey

### The Iterative Process

This project involved **constant iteration and improvement**. Each module went through multiple versions based on feedback and learning.

### Login Module Evolution

**Version 1.0** (Days 10-11):
```
Status: Basic functionality
Tests: 6 (valid/invalid login)
Issues: No security tests, repetitive code, no cross-browser
```

**Version 2.0** (Day 11-12):
```
Status: Added security
Tests: 19 (added SQL injection, XSS)
Issues: Not parametrized, slow reporting, still repetitive
```

**Version 3.0** (Day 12):
```
Status: Parametrized tests
Tests: 33 (parametrized security tests)
Issues: No cross-browser, logging could be better
```

**Version 3.1** (Day 13):
```
Status: Production-ready
Tests: 33 (same count, enhanced features)
Features: Cross-browser, real-time logging, improved helpers
Issues: Needs restructuring (1 file vs 2)
```

### Purchase Module Evolution

**Version 1.0** (Day 15):
```
Status: Single file approach
Tests: 28 functional
Issues: No security tests, growing file size, hard to navigate
```

**Version 2.0** (Day 15):
```
Status: Added security tests
Tests: 40 in one file
Issues: File too large (2000+ lines), hard to maintain
```

**Version 3.0** (Day 16):
```
Status: Split into two files
Structure: 
  - test_purchase.py (functional)
  - test_purchase_business_rules.py (validation)
Issues: Still combined functional and business rules
```

**Version 4.0** (Day 17 - Current):
```
Status: Final structure
Structure:
  - functional-tests/test_purchase.py (28 tests)
  - security-tests/test_purchase_security.py (28 tests)
Features: Proper separation, each test cites standards
Issues: None - this is the template for future modules
```

### Key Improvements Made

**Code Organization**:
- Started: Everything in one file
- Now: Modular structure with clear separation

**Test Design**:
- Started: Tests that assume behavior
- Now: Tests that discover behavior

**Documentation**:
- Started: Basic comments
- Now: 13,255 lines of comprehensive documentation

**Reusability**:
- Started: DemoBlaze-specific code
- Now: Generic templates for any web app

**Standards**:
- Started: No standard references
- Now: Every business rule cites specific standards

---

## Repository Structure

```
demoblaze-testing-project/
│
├── docs/                                   # Test planning & documentation
│   ├── test-plan.md                        # Comprehensive test strategy
│   ├── users-flow.md                       # 10 user flow scenarios
│   ├── DemoBlaze_Test_Cases.xlsx           # 36 manual test cases
│   └── Test summary report                 # Phase 2 results
│
├── templates/                              # Reusable testing templates
│   ├── Functionality/
│   │   ├── Guide/
│   │   │   └── functional_template_complete_guide.md
│   │   └── Part1/
│   │       └── template_functional_business_rules_v2.md
│   └── Security/
│       ├── Guide/
│       │   └── Security_template_complete_guide.md
│       └── Part1/
│           └── Template_security_exploitation_part1.md
│
├── tests/                                  # Automated test suites
│   ├── login/                              # Login module (needs refactoring)
│   │   ├── test_dem_login.py               # 33 tests (1 file - should be 2)
│   │   └── README.md                       # 1,422 lines documentation
│   │
│   ├── purchase/                           # Purchase module (correct structure)
│   │   ├── functional-tests/
│   │   │   ├── test_purchase.py            # 28 functional tests
│   │   │   └── README.md                   # 1,428 lines documentation
│   │   └── security-tests/
│   │       ├── test_purchase_security.py   # 28 security tests
│   │       └── README.md                   # 1,400 lines documentation
│   │
│   └── signup/                             # Signup module
│       ├── test_signup.py                  # 30 tests
│       └── README_signup.md                # Comprehensive documentation
│
├── conftest.py                             # Pytest configuration (needs update)
├── requirements.txt                        # Python dependencies
└── README.md                               # This file

Total: 3,390 lines Python | 13,255 lines Markdown
```

---

## Installation & Usage

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git (for cloning repository)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/demoblaze-testing-project.git
cd demoblaze-testing-project

# Install dependencies
pip install -r requirements.txt
```

### Running Tests

**Run all tests**:
```bash
pytest
```

**Run specific module**:
```bash
pytest tests/login/
pytest tests/purchase/functional-tests/
pytest tests/purchase/security-tests/
pytest tests/signup/
```

**Cross-browser testing**:
```bash
pytest tests/login/ --browser=chrome
pytest tests/login/ --browser=firefox
pytest tests/login/ --browser=edge
```

**Run with verbose output**:
```bash
pytest tests/login/ -v
```

**Run with live logging**:
```bash
pytest tests/login/ -s
```

**Run specific test function**:
```bash
pytest tests/login/test_dem_login.py::test_login_valid_credentials
```

**Run tests by marker**:
```bash
pytest -m functional              # Only functional tests
pytest -m business_rules          # Only business rules
pytest -m "not xfail"             # Exclude expected failures
```

### HTML Reports

Reports are automatically generated in `test_results/` directory:

```bash
pytest tests/login/
# Report: test_results/login/report_chrome_2025-11-14_10-30-00.html
```

---

## Key Learnings

### QA Fundamentals

**Before this project**:
- No understanding of test planning
- Didn't know difference between test case and test scenario
- No knowledge of bug severity vs priority

**After 20 days**:
- Can create comprehensive test plans
- Understand test design techniques (equivalence partitioning, boundary analysis)
- Know when to use manual vs automated testing
- Can classify bugs by severity and impact

### Technical Skills

**Selenium & Web Automation**:
- Browser automation fundamentals
- Element location strategies (ID, XPath, CSS)
- Explicit vs implicit waits
- Cross-browser testing
- Handling alerts and modals

**Python & Pytest**:
- Pytest framework architecture
- Fixtures for setup/teardown
- Parametrized tests
- Test markers and organization
- Helper functions and DRY principle

**Security Testing**:
- SQL Injection detection
- XSS testing
- CSRF token validation
- Input validation testing
- Business logic vulnerabilities

### Professional Practices

**Code Quality**:
- DRY (Don't Repeat Yourself)
- Single Responsibility Principle
- Explicit over implicit
- Configuration separation
- Comprehensive documentation

**Testing Standards**:
- OWASP Top 10 security risks
- ISO 25010 software quality model
- PCI-DSS payment security
- WCAG accessibility standards
- NIST authentication guidelines

**Development Workflow**:
- Git version control
- Meaningful commit messages
- Code review process
- Iterative improvement
- Documentation as code

### Soft Skills

**Problem Solving**:
- Debugging test failures systematically
- Breaking down complex problems
- Asking the right questions

**Self-Learning**:
- Using AI as a learning tool
- Knowing when to accept vs reject AI suggestions
- Building mental models of new concepts

**Communication**:
- Writing clear documentation
- Explaining technical concepts
- Creating user-focused content

**Persistence**:
- 20 days of continuous learning
- Multiple code iterations
- Not settling for "good enough"

---

## What's Next

### Short Term (1-2 weeks)

**Login Module Refactoring**:
- Split into functional-tests/ and security-tests/
- Match Purchase module structure
- Update documentation

**Conftest.py Update**:
- Align with current fixture patterns
- Add support for both file structures
- Improve browser configuration

**E2E Tests**:
- Complete user journey testing
- Multi-step workflows (signup → login → purchase)
- State persistence validation

### Medium Term (1 month)

**Additional Test Modules**:
- Catalog/Product browsing
- Contact form
- About/Footer sections

**Page Object Model (POM)**:
- Refactor to POM design pattern
- Create page classes
- Improve maintainability

**CI/CD Pipeline**:
- GitHub Actions workflow
- Automated test execution on push
- Test result notifications

### Long Term (3 months)

**API Testing Layer**:
- Learn API testing fundamentals
- Test DemoBlaze API endpoints
- Compare UI vs API test results

**Performance Testing**:
- Basic load testing
- Response time validation
- Resource usage monitoring

**Advanced Reporting**:
- Allure reports
- Test trend analysis
- Coverage metrics dashboard

---

## For Recruiters

### What This Project Demonstrates

**Technical Competency**:
- Can build test automation from scratch
- Understands security testing fundamentals
- Writes clean, maintainable code
- Creates comprehensive documentation

**Learning Ability**:
- Went from zero to 119 automated tests in 20 days
- Learned Python, Selenium, and Pytest simultaneously
- Applied industry standards (OWASP, ISO 25010)
- Created reusable templates for future projects

**Professional Maturity**:
- Transparent about AI usage (shows honesty)
- Documents mistakes and iterations (shows growth mindset)
- Doesn't oversell incomplete work (shows integrity)
- Seeks continuous improvement (shows dedication)

**Real-World Skills**:
- Test planning and strategy
- Manual and automated testing
- Bug tracking and reporting
- Cross-browser testing
- Security vulnerability detection

### Project Highlights

- **119 automated tests** across 3 modules
- **29 bugs discovered** through manual testing
- **13,255 lines** of professional documentation
- **4 reusable templates** for future projects
- **Multiple code iterations** demonstrating improvement
- **Industry standards** referenced in every test

### What Makes This Different

**Not a tutorial project**: Every line of code was reviewed, understood, and tested by me.

**Not copy-paste**: Multiple versions of each module showing real learning progression.

**Not surface-level**: Comprehensive documentation explaining every decision and technique.

**Not just passing tests**: Tests that discover bugs and cite specific standards.

**Not finished**: Honest about what's complete and what needs work.

---

## Acknowledgments

### Learning Resources

**AI Assistants**:
- Claude AI (Anthropic) - Primary learning partner
- Gemini (Google) - Secondary reference

**Open Source Tools**:
- Selenium - Browser automation
- Pytest - Test framework
- webdriver-manager - Driver management

**Testing Community**:
- DemoBlaze - Practice application
- OWASP - Security standards
- ISO - Software quality standards

### Special Recognition

**To myself**: For committing to 20 days of intensive learning, not accepting "good enough," and pushing through multiple code iterations until getting it right.

**To the QA community**: For open-source tools and knowledge sharing that make learning accessible.

**To future me**: This project represents where I started. Keep building on this foundation.

---

## Contact

**Author**: Marc Arévalo  
**Project**: QA Testing Learning Portfolio  
**Duration**: November 2025 (20 days)  
**Status**: Active Development

**GitHub**: HOW I DO THIS? 
**Email**: marcarevalocano@gmail.com
**Discussions**: Available in GitHub Discussions tab

**Open to**:
- Questions about the project
- Collaboration opportunities
- Feedback and suggestions
- Mentoring discussions (I'm learning too!)

**Response Time**: Usually within 12 hours
 
---

## License

This project is for educational and portfolio purposes. Feel free to learn from it, but please don't claim the work as entirely your own if you use AI assistance.

---

## Final Note

This README documents a learning journey, not a perfect product. If you're learning QA Testing too, I hope this shows you that:

1. It's okay to use AI as a learning tool
2. Multiple iterations are normal and expected
3. Documentation is as important as code
4. Transparency about your process is valuable
5. 20 days of focused work can accomplish a lot

**Keep learning. Keep testing. Keep documenting.**

---

**Last Updated**: November 14, 2025  
**Version**: 2.0  
