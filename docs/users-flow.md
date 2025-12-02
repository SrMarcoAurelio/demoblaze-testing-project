# User Flows - DemoBlaze

## Flow 1: Guest User Purchase (No Registration)
**Actor:** Guest user
**Objective:** Purchase a product without creating an account

**Steps:**
1. Access demoblaze.com
2. Browse products on the homepage
3. Select a category (Phones/Laptops/Monitors)
4. Click on a specific product
5. Click "Add to cart"
6. Accept the alert confirmation
7. Click "Cart" in the navigation menu
8. Click "Place Order"
9. Fill out purchase form (Name, Country, City, Credit card, Month, Year)
10. Click "Purchase"
11. Verify purchase confirmation popup

**Expected Result:** Purchase completes successfully without login requirement

**Actual Result:** [To be tested]

---

## Flow 2: New User Registration
**Actor:** New user
**Objective:** Create a new account

**Steps:**
1. Access demoblaze.com
2. Click "Sign up" in the navigation menu
3. Enter username in the username field
4. Enter password in the password field
5. Click "Sign up" button
6. Observe success/error alert

**Expected Result:** Account is created successfully with confirmation message

**Actual Result:** [To be tested]

---

## Flow 3: Registered User Login
**Actor:** Registered user
**Objective:** Log in to existing account

**Steps:**
1. Access demoblaze.com
2. Click "Log in" in the navigation menu
3. Enter valid username
4. Enter valid password
5. Click "Log in" button
6. Verify username appears in navigation ("Welcome [username]")

**Expected Result:** User successfully logs in and username is displayed

**Actual Result:** [To be tested]

---

## Flow 4: Login with Invalid Credentials (Negative Test)
**Actor:** Any user
**Objective:** Attempt login with wrong credentials

**Steps:**
1. Access demoblaze.com
2. Click "Log in"
3. Enter non-existent username
4. Enter random password
5. Click "Log in" button
6. Observe error message

**Expected Result:** Clear error message like "User does not exist" or "Wrong password"

**Actual Result:** [To be tested]

---

## Flow 5: Add Multiple Products to Cart
**Actor:** Any user
**Objective:** Add multiple different products to cart

**Steps:**
1. Access demoblaze.com
2. Click on first product (e.g., Samsung Galaxy S6)
3. Click "Add to cart" and accept alert
4. Click "Home" to return
5. Click on second product (e.g., Nokia Lumia 1520)
6. Click "Add to cart" and accept alert
7. Click "Cart" in navigation
8. Verify both products appear in cart
9. Verify total price is correct

**Expected Result:** Both products listed separately with correct total

**Actual Result:** [To be tested]

---

## Flow 6: Remove Product from Cart
**Actor:** Any user
**Objective:** Delete a product from the shopping cart

**Steps:**
1. Access demoblaze.com
2. Add a product to cart (follow Flow 1 steps 1-7)
3. In cart view, click "Delete" link next to product
4. Observe product is removed
5. Verify total price updates or shows empty cart

**Expected Result:** Product is removed and cart updates correctly

**Actual Result:** [To be tested]

---

## Flow 7: Browse Products by Category
**Actor:** Any user
**Objective:** Filter products by category

**Steps:**
1. Access demoblaze.com
2. Click "Phones" in the left sidebar
3. Verify only phone products are displayed
4. Click "Laptops" in the left sidebar
5. Verify only laptop products are displayed
6. Click "Monitors" in the left sidebar
7. Verify only monitor products are displayed

**Expected Result:** Products filter correctly by selected category

**Actual Result:** [To be tested]

---

## Flow 8: Contact Form Submission
**Actor:** Any user
**Objective:** Send a message through contact form

**Steps:**
1. Access demoblaze.com
2. Click "Contact" in navigation menu
3. Enter email address in "Contact Email" field
4. Enter name in "Contact Name" field
5. Enter message in "Message" field
6. Click "Send message" button
7. Observe confirmation alert

**Expected Result:** Message sent successfully with confirmation

**Actual Result:** [To be tested]

---

## Flow 9: Product Pagination/Navigation
**Actor:** Any user
**Objective:** Navigate through multiple pages of products

**Steps:**
1. Access demoblaze.com
2. Scroll to bottom of product list
3. Click "Next" button
4. Verify new products load
5. Click "Previous" button
6. Verify previous products reload

**Expected Result:** Navigation works smoothly between product pages

**Actual Result:** [To be tested]

---

## Flow 10: Logged-in User Logout
**Actor:** Logged-in user
**Objective:** Log out from the account

**Steps:**
1. Access demoblaze.com (already logged in)
2. Verify "Welcome [username]" appears in navigation
3. Click "Log out" in navigation menu
4. Verify "Log out" changes back to "Log in"
5. Verify "Welcome [username]" disappears

**Expected Result:** User successfully logs out and UI updates

**Actual Result:** [To be tested]
