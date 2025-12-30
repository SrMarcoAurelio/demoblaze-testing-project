# Code Generators - Planned Feature

**Status:** 🚧 Planned for future releases (v7.0+)

## Overview

This directory is reserved for **code generation tools** that will automate creation of page objects, test files, and locators.

## Planned Generators

### 1. Page Object Generator
**File:** `page_generator.py` (Planned)

**Purpose:** Automatically generate page object classes by analyzing web pages.

**Usage (Planned):**
```bash
# Generate page object by analyzing live page
python -m framework.generators.page_generator \
    --url https://app.example.com/login \
    --output pages/login_page.py
```

**Features (Planned):**
- Crawl page and detect elements
- Identify forms, buttons, links automatically
- Generate Python class with locators
- Create methods based on interactive elements
- Support for Shadow DOM and iframes

### 2. Test Generator
**File:** `test_generator.py` (Planned)

**Purpose:** Generate test skeletons based on page objects.

**Usage (Planned):**
```bash
# Generate tests from existing page object
python -m framework.generators.test_generator \
    --page-object pages/login_page.py \
    --output tests/test_login.py
```

**Features (Planned):**
- Analyze page object methods
- Generate test cases for each method
- Add fixtures automatically
- Include assertions placeholders
- Follow pytest conventions

### 3. Locator Generator
**File:** `locator_generator.py` (Planned)

**Purpose:** Extract locators from HTML and generate JSON/Python files.

**Usage (Planned):**
```bash
# Extract locators from HTML file
python -m framework.generators.locator_generator \
    --html captured_page.html \
    --output config/locators.json
```

**Features (Planned):**
- Parse HTML/DOM
- Generate optimal selectors (ID > name > CSS > XPath)
- Export to JSON or Python dict
- Validate uniqueness of selectors
- Group by semantic regions

## Why Not Implemented Yet?

These generators require:
1. **Complex DOM analysis** - Reliable element detection
2. **AI/ML integration** - Smart element identification (optional)
3. **Template engine** - Code generation from templates
4. **Extensive testing** - Ensure generated code works across browsers

**Priority:** Medium - Nice to have, but manual creation is acceptable

## Workaround Until Implementation

Use templates manually:

```bash
# Instead of page generator:
cp templates/page_objects/__template_login_page.py pages/login_page.py
# Manually edit locators

# Instead of test generator:
cp templates/test_files/__template_functional_test.py tests/test_login.py
# Manually edit test logic

# Instead of locator generator:
# Use browser DevTools to inspect elements
# Manually add to config/locators.json
```

## Community Contributions Welcome

If you'd like to implement these generators:

1. Fork the repository
2. Create feature branch: `feature/page-generator`
3. Implement generator following framework patterns
4. Add comprehensive tests
5. Update documentation
6. Submit pull request

**See:** `CONTRIBUTING.md` for contribution guidelines

## Related Tools

While we build this feature, consider using:

- **Selenium IDE** - Record and export to code
- **Playwright Codegen** - Generate Playwright code (adapt to Selenium)
- **Manual inspection** - Browser DevTools (F12) for locators

## Technical Approach (When Implemented)

### Page Object Generator Architecture
```python
class PageGenerator:
    """Generate page objects from live pages."""

    def crawl_page(self, url: str) -> dict:
        """Crawl page and extract structure."""
        pass

    def identify_elements(self, dom: dict) -> List[Element]:
        """Identify interactive elements."""
        pass

    def generate_locators(self, elements: List[Element]) -> dict:
        """Generate optimal locators."""
        pass

    def generate_class(self, locators: dict) -> str:
        """Generate Python class code."""
        pass
```

### Challenges to Solve
1. **Dynamic content** - JavaScript-rendered elements
2. **Shadow DOM** - Encapsulated components
3. **Naming** - Generate meaningful method names
4. **Ambiguity** - Multiple similar elements
5. **Maintainability** - Ensure generated code is readable

## Timeline (Tentative)

- **v7.0** (Q2 2026) - Basic page object generator
- **v7.1** (Q3 2026) - Test generator
- **v7.2** (Q4 2026) - Locator generator
- **v8.0** (Q1 2027) - AI-assisted element identification

## Feedback Welcome

If you have ideas or requirements for these generators, please:
- Open an issue: https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues
- Label: `enhancement`, `generators`
- Describe your use case

---

**Note:** This directory exists to signal future direction. Check back in future releases for implementation.
