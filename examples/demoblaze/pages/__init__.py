# -*- coding: utf-8 -*-
"""
Page Objects - DemoBlaze Test Automation
Author: Marc Arevalo

Page Object Model implementation for DemoBlaze website.
"""

from pages.base_page import BasePage
from pages.cart_page import CartPage
from pages.catalog_page import CatalogPage
from pages.login_page import LoginPage
from pages.product_page import ProductPage
from pages.purchase_page import PurchasePage
from pages.signup_page import SignupPage

__all__ = [
    "BasePage",
    "CartPage",
    "CatalogPage",
    "LoginPage",
    "ProductPage",
    "PurchasePage",
    "SignupPage",
]
