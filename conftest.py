"""
Pytest Configuration File
Author: Arévalo, Marc
Description: Global pytest configuration for DemoBlaze test automation project.
             Provides cross-browser support and automatic HTML report generation.
Version: 2.0
"""

import pytest
import os
import datetime
import logging

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')

TIMEOUT = 10


def pytest_addoption(parser):
    parser.addoption(
        "--browser", 
        action="store", 
        default="chrome", 
        help="Choose browser: chrome, firefox, or edge"
    )


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    results_root_dir = "test_results"
    report_group = "general"
    
    try:
        if config.args:
            test_path_str = str(config.args[0])
            norm_path = os.path.normpath(test_path_str)
            
            if os.path.isdir(norm_path):
                group_name = os.path.basename(norm_path)
            else:
                group_name = os.path.basename(os.path.dirname(norm_path))
            
            if group_name not in ["tests", ".", ""]:
                report_group = group_name
    except Exception as e:
        logging.warning(f"Could not detect report group, using 'general'. Error: {e}")
        report_group = "general"
        
    report_dir = os.path.join(results_root_dir, report_group)
    os.makedirs(report_dir, exist_ok=True)
    
    browser_name = config.getoption("--browser").lower()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"report_{browser_name}_{timestamp}.html"
    report_path = os.path.join(report_dir, report_name)
    
    config.option.htmlpath = report_path
    config.option.self_contained_html = True
    
    logging.info(f"HTML report will be generated at: {report_path}")


@pytest.fixture(scope="function")
def browser(request):
    browser_name = request.config.getoption("--browser").lower()
    driver = None
    logging.info(f"\n--- Starting WebDriver for: {browser_name} ---")

    if browser_name == "chrome":
        service = Service(ChromeDriverManager().install())
        options = webdriver.ChromeOptions()
        driver = webdriver.Chrome(service=service, options=options)
    
    elif browser_name == "firefox":
        service = Service(GeckoDriverManager().install())
        options = webdriver.FirefoxOptions()
        driver = webdriver.Firefox(service=service, options=options)
    
    elif browser_name == "edge":
        service = Service(EdgeChromiumDriverManager().install())
        options = webdriver.EdgeOptions()
        driver = webdriver.Edge(service=service, options=options)
    
    else:
        pytest.fail(f"Browser '{browser_name}' is not supported. Choose 'chrome', 'firefox', or 'edge'.")

    driver.maximize_window()
    driver.implicitly_wait(TIMEOUT)
    
    yield driver
    
    driver.quit()
    logging.info(f"--- WebDriver {browser_name} Closed ---")
