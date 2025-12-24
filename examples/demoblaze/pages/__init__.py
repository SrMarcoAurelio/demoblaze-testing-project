# -*- coding: utf-8 -*-
"""
Page Objects - DemoBlaze Test Automation
Author: Marc Arevalo

Page Object Model implementation for DemoBlaze website.
"""

from .base_page import BasePage
from .cart_page import CartPage
from .catalog_page import CatalogPage
from .login_page import LoginPage
from .product_page import ProductPage
from .purchase_page import PurchasePage
from .signup_page import SignupPage

__all__ = [
    "BasePage",
    "CartPage",
    "CatalogPage",
    "LoginPage",
    "ProductPage",
    "PurchasePage",
    "SignupPage",
]
