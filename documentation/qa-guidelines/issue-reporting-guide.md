# Issue Reporting Guide - Quality Assurance Standards

## 📋 **Table of Contents**
1. [Introduction](#introduction)
2. [QA Mindset](#qa-mindset)
3. [Issue Reporting Methodology](#issue-reporting-methodology)
4. [Issue Report Structure](#issue-report-structure)
5. [Testing Criteria](#testing-criteria)
6. [Examples](#examples)
7. [Best Practices](#best-practices)

---

## 🎯 **Introduction**

As a Quality Assurance professional, your role extends beyond simply executing test cases. You are the **last line of defense** before software reaches users. This guide outlines how to properly identify, document, and report issues.

**Remember:** If something seems wrong, unusual, or doesn't make sense - it probably is. Report it.

---

## 🧠 **QA Mindset**

### **Your Responsibilities:**

1. **Verify Everything Works** - Not just the specific bug, but the entire feature
2. **Discover New Issues** - Don't limit yourself to predefined test cases
3. **Question Everything** - If something doesn't make sense, ask why
4. **Think Like a User** - Consider real-world usage scenarios
5. **Protect the Product** - You represent the end users

### **Critical Thinking:**

- ❓ **Why does this button exist?**
- ❓ **What happens if a user does X instead of Y?**
- ❓ **Does this meet UX/UI standards?**
- ❓ **Is this accessible to all users?**
- ❓ **Could this confuse users?**

**Example:** You find a button that seems useless. **Don't ignore it.** Report it and ask IT why it exists. If a manager later asks "Why didn't you catch this?" you need to have done your due diligence.

---

## 🔍 **Issue Reporting Methodology**

### **1. Problem Statement**

Clearly define what you observed:

```
WHAT: Describe the issue
WHERE: Which page/feature
WHEN: Under what conditions
WHO: Which user role/type
```

### **2. Expected vs Actual Behavior**

```
EXPECTED: What should happen according to requirements/standards
ACTUAL: What actually happened
IMPACT: How does this affect users?
```

### **3. Reproducibility**

```
STEPS TO REPRODUCE:
1. Navigate to [page]
2. Click [element]
3. Enter [data]
4. Observe [result]

FREQUENCY: Always / Sometimes / Rare
ENVIRONMENT: Browser, OS, version
```

### **4. Evidence**

- Screenshots with annotations
- Screen recordings for complex issues
- Console logs (browser developer tools)
- Network requests (if applicable)
- Error messages (full text)

### **5. Severity Assessment**

- **CRITICAL**: Blocks core functionality, data loss, security
- **HIGH**: Major feature broken, workaround difficult
- **MEDIUM**: Feature partially broken, workaround exists
- **LOW**: Cosmetic, minor inconvenience, easy workaround

---

## 📝 **Issue Report Structure**

### **Template:**

```markdown
## 🐛 [Component] Brief Description

**Priority:** Critical / High / Medium / Low
**Type:** Bug / Enhancement / Question / Standards Violation

### Problem Statement
[Clear description of the issue]

### Environment
- Browser: Chrome 120
- OS: Windows 11
- Screen Resolution: 1920x1080
- User Role: Admin / Standard User

### Expected Behavior
[What should happen according to specs/standards]

### Actual Behavior
[What actually happens]

### Steps to Reproduce
1. Go to login page
2. Enter valid credentials
3. Click "Login"
4. Observe error despite valid data

### Evidence
- Screenshot: [attach]
- Console Error: [paste]
- Network Request: [attach HAR file]

### Impact
- Users cannot login
- Blocks all functionality
- Affects 100% of users

### Additional Context
- First noticed: 2024-12-09 10:30 AM
- Related to recent deployment: Yes/No
- Workaround available: Yes/No
- Standards violated: WCAG 2.1 / Design System

### Suggested Fix (Optional)
[If you have insights on potential solution]
```

---

## ✅ **Testing Criteria**

### **Functional Testing:**

When testing a feature (e.g., Login):

**Don't just test:**
- ✓ Valid credentials work

**Also test:**
- ✓ Invalid credentials fail appropriately
- ✓ Empty fields show proper validation
- ✓ Special characters are handled
- ✓ SQL injection attempts are blocked
- ✓ Error messages are user-friendly
- ✓ "Forgot Password" link works
- ✓ "Remember Me" persists correctly
- ✓ Session timeout works
- ✓ Logout clears session
- ✓ Back button behavior after logout
- ✓ Multiple failed login attempts are handled
- ✓ Keyboard navigation works (Tab, Enter)
- ✓ Screen readers announce properly
- ✓ Mobile responsive
- ✓ Performance under load

**Think:** What could break? What would users try?

### **Standards Compliance:**

Report violations of:

1. **Accessibility Standards (WCAG 2.1)**
   - Missing alt text on images
   - Poor color contrast
   - No keyboard navigation
   - Missing ARIA labels

2. **UX/UI Standards**
   - Inconsistent button styles
   - Confusing navigation
   - Poor mobile experience
   - Misleading labels

3. **Security Standards**
   - Passwords shown in plain text
   - No input sanitization
   - Exposed sensitive data
   - Missing HTTPS

4. **Performance Standards**
   - Page load > 3 seconds
   - Memory leaks
   - Unnecessary network requests

### **Useless/Confusing Elements:**

**If you find:**
- A button that does nothing → Report it
- A field that seems unnecessary → Ask why it exists
- Misleading labels → Suggest improvements
- Broken links → Document them
- Dead code visible to users → Flag it

**Reasoning:** If IT later says "Why didn't you catch this?" you need proof you did your job. Document everything suspicious.

---

## 💡 **Examples**

### **Example 1: Discovering New Issues**

**Assigned Bug:** "Login button not responding"

**Your Testing:**
1. ✅ Verify login button works (bug fixed)
2. 🔍 **But wait...** password field shows text instead of dots
3. 🔍 **Also found...** no validation for empty username
4. 🔍 **Additionally...** "Forgot Password" link is broken
5. 🔍 **Moreover...** error message reveals if username exists (security risk)

**Result:** You found 1 fixed bug + 4 new critical issues

### **Example 2: Questioning Design**

**Scenario:** Testing checkout page

**Observation:** There's a "Save for Later" button that does nothing

**Wrong Approach:** ❌ Ignore it (not in test case)

**Correct Approach:** ✅ Report it
```
Title: [Checkout] "Save for Later" button has no functionality

Description:
The "Save for Later" button on checkout page appears to do nothing
when clicked. No visual feedback, no items saved, no error.

Questions for IT:
1. Is this button supposed to be functional?
2. If yes, it's broken and needs fixing
3. If no, it should be removed (confuses users)
4. If it's for future implementation, should be disabled with tooltip

Impact: Users click expecting functionality, get confused
Recommendation: Either implement or remove to avoid user frustration
```

### **Example 3: Standards Violation**

**Scenario:** Testing product images

**Observation:** Images load but have no alt text

**Report:**
```
Title: [Accessibility] Product images missing alt text - WCAG 2.1 Violation

Priority: HIGH (Legal compliance issue)

Description:
All product images on catalog page are missing alt text attributes.
This violates WCAG 2.1 Level A (1.1.1 Non-text Content).

Impact:
- Screen reader users cannot understand product images
- Fails accessibility audit
- Potential legal compliance issue (ADA, Section 508)
- SEO impact (search engines can't index images)

Evidence:
<img src="product1.jpg">  ← Missing alt attribute

Expected:
<img src="product1.jpg" alt="Samsung Galaxy S23 - Black, 256GB">

Standards Violated:
- WCAG 2.1 Level A: 1.1.1 Non-text Content
- Section 508: § 1194.22(a)

Recommendation:
Add descriptive alt text to all product images. Format:
"[Product Name] - [Key Features/Color]"
```

---

## 🌟 **Best Practices**

### **DO:**

✅ **Test beyond the happy path** - Users won't always follow instructions
✅ **Document everything** - Screenshots, videos, logs
✅ **Ask questions** - If something seems odd, investigate
✅ **Think like a hacker** - Try to break things intentionally
✅ **Consider accessibility** - Not everyone uses mouse & screen
✅ **Check mobile** - Most users are on mobile devices
✅ **Verify data integrity** - Ensure data saves/loads correctly
✅ **Test edge cases** - Maximum input, special characters, etc.
✅ **Report design issues** - Bad UX is a bug too
✅ **Follow up** - Verify fixes actually work

### **DON'T:**

❌ **Assume it's "supposed to work that way"** - Ask
❌ **Skip reporting because "it's minor"** - Let management prioritize
❌ **Test only what's in the test case** - Explore and discover
❌ **Ignore your intuition** - If it feels wrong, investigate
❌ **Accept "works on my machine"** - Reproduce in target environment
❌ **Report without evidence** - Always include proof
❌ **Be vague** - Specific steps to reproduce are critical
❌ **Test in isolation** - Consider integration with other features

### **Communication:**

- **Be clear and concise** - Developers are busy
- **Be professional** - "The login is broken" not "The login sucks"
- **Be helpful** - Suggest potential causes/solutions
- **Be persistent** - Follow up on unresolved issues
- **Be collaborative** - Work with dev team, not against them

---

## 🎓 **Remember:**

> **"Quality is not an act, it is a habit."** - Aristotle

Your job is not just to find bugs. Your job is to ensure the product is:
- ✅ Functional (works as intended)
- ✅ Usable (users can accomplish tasks)
- ✅ Accessible (everyone can use it)
- ✅ Secure (protects user data)
- ✅ Performant (fast and responsive)
- ✅ Standards-compliant (meets regulations)

**When in doubt, report it.** It's better to over-communicate than to miss critical issues.

---

## 📞 **Questions?**

If you're unsure whether something should be reported:
1. Ask yourself: "Would this confuse/frustrate a user?"
2. If YES → Report it
3. If MAYBE → Report it with question tag
4. If NO → Still document it in notes

**Golden Rule:** If management asks "Why didn't you catch this?" you should be able to show you did your due diligence.

---

*Last Updated: 2024-12-09*
*Version: 1.0*
