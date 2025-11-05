import pytest
import os
import datetime

def pytest_addoption(parser):
    parser.addoption(
        "--browser", 
        action="store", 
        default="chrome", 
        help="Elige el navegador: chrome, firefox, o edge"
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
        print(f"No se pudo detectar el grupo del reporte, se usará 'general'. Error: {e}")
        report_group = "general"
        
    report_dir = os.path.join(results_root_dir, report_group)
    
    os.makedirs(report_dir, exist_ok=True)
    
    browser_name = config.getoption("--browser").lower()
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    report_name = f"report_{browser_name}_{timestamp}.html"
    
    report_path = os.path.join(report_dir, report_name)
    
    config.option.htmlpath = report_path
    
    config.option.self_contained_html = True
