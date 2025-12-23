# Shopping Cart Tests

## Overview

Comprehensive test suite for shopping cart functionality including add/remove operations, price calculations, and cart persistence.

## Test Files

- `test_cart_functional.py` - Core cart operations (20 tests)
- `test_cart_business.py` - Business logic validation (15 tests)
- `test_cart_accessibility.py` - WCAG 2.1 compliance (8 tests)
- `test_cart_performance.py` - Performance benchmarks (12 tests)

## Test Coverage (55 tests total)

### Functional Tests
- Add products to cart
- Remove products from cart
- Update quantities
- Cart persistence across sessions
- Empty cart handling
- Multiple product management

### Business Logic Tests
- Price calculations
- Discount application
- Tax calculations (if applicable)
- Inventory availability checks
- Maximum quantity limits

### Accessibility Tests (WCAG 2.1 Level AA)
- Keyboard navigation
- Screen reader compatibility
- ARIA labels validation
- Color contrast verification

### Performance Tests
- Cart loading time
- Add to cart response time
- Bulk operations performance

## Running Tests

```bash
# All cart tests
pytest tests/cart/ -v

# Specific category
pytest tests/cart/test_cart_functional.py -v
pytest -m cart -v

# With coverage
pytest tests/cart/ --cov=pages.cart_page
```

## Page Object

Uses `pages/cart_page.py` (281 lines, CartPage class)

**Key Methods:**
- `get_cart_items()` - Retrieve cart items
- `get_total_price()` - Calculate total
- `remove_item(product_name)` - Remove product
- `place_order()` - Navigate to checkout

## Test Data

Sample cart data in `tests/static_test_data.py`:
- Product IDs and names
- Expected prices
- Test scenarios (empty cart, single item, multiple items)

## Standards

- ISO 25010 (Software Quality)
- WCAG 2.1 Level AA (Accessibility)
- Core Web Vitals (Performance)

## Maintenance

Update tests when:
- Cart UI changes
- Pricing logic modified
- New cart features added
- Performance thresholds change

## Common Issues

### Issue: Price Mismatch

Check if tax or discounts are being applied correctly.

### Issue: Cart Not Persisting

Verify localStorage/sessionStorage handling in cart_page.py.

## License

Internal test suite - follows project license.
