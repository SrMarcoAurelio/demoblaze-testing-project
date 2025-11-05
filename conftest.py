# conftest.py (Versión 3.0 - Soporta grupos de reportes)
import pytest
import os
import datetime

def pytest_addoption(parser):
    """
    Añade opciones de línea de comandos a pytest.
    """
    # Opción para elegir el navegador
    parser.addoption(
        "--browser", 
        action="store", 
        default="chrome", 
        help="Elige el navegador: chrome, firefox, o edge"
    )
    
    # NUEVA OPCIÓN: para agrupar reportes
    parser.addoption(
        "--report-group", 
        action="store", 
        default="general", 
        help="Define un subdirectorio para los reportes (ej: login, purchase)"
    )

@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    """
    Hook para configurar la ruta del reporte HTML automáticamente
    antes de que los tests comiencen.
    """
    
    # 1. Definir la carpeta raíz de resultados
    results_root_dir = "test_results"
    
    # 2. Leer el grupo de reporte (ej: "login") de la nueva opción
    report_group = config.getoption("--report-group").lower()
    
    # 3. Crear la ruta de la subcarpeta (ej: "test_results/login")
    report_dir = os.path.join(results_root_dir, report_group)
    
    # 4. Crear las carpetas si no existen
    os.makedirs(report_dir, exist_ok=True)
    
    # 5. Leer el navegador que se usará (ej: "chrome")
    browser_name = config.getoption("--browser").lower()
    
    # 6. Crear un timestamp único
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # 7. Crear el nombre de archivo del reporte
    report_name = f"report_{browser_name}_{timestamp}.html"
    
    # 8. Definir la ruta completa del reporte
    # (ej: "test_results/login/report_chrome_2025-11-05_17-30-00.html")
    report_path = os.path.join(report_dir, report_name)
    
    # 9. Asignar esta ruta a la configuración de pytest-html
    config.option.htmlpath = report_path
    
    # 10. Activar automáticamente el 'self-contained-html'
    config.option.self_contained_html = True
