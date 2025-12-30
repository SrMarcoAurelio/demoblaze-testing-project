# Command-Line Interface Tools

CLI tools for framework setup, configuration, and management.

## Available Tools

### `setup_wizard.py` - Interactive Configuration

Advanced setup wizard for framework configuration. More comprehensive than `quick_start.py`.

**Usage:**
```bash
python -m framework.cli.setup_wizard
```

**Features:**
- [Yes] Interactive prompts for all settings
- [Yes] Basic configuration (URL, browser, timeouts)
- [Yes] Advanced configuration (Grid, performance, parallel)
- [Yes] Generates `.env` file with comments
- [Yes] Validates user input
- [Yes] Shows next steps after setup

**When to Use:**
- Initial framework setup
- Reconfiguring for new environment
- Setting up Selenium Grid
- Configuring performance thresholds

**Differences from quick_start.py:**

| Feature | quick_start.py | setup_wizard.py |
|---------|----------------|-----------------|
| **Purpose** | Quick onboarding | Full configuration |
| **Location** | Project root | framework/cli/ |
| **Dependencies check** | [Yes] Yes | [No] No |
| **Runs tests** | [Yes] Yes | [No] No |
| **Advanced settings** | [No] No | [Yes] Yes |
| **Grid support** | [No] No | [Yes] Yes |
| **Performance config** | [No] No | [Yes] Yes |

**Recommendation:**
- New users: Run `quick_start.py` first
- Experienced users: Use `setup_wizard.py` for full control

## Planned Tools (Future Releases)

### `validate.py` - Configuration Validator (Planned for v7.0)
Validate framework configuration and dependencies.

```bash
python -m framework.cli.validate
```

Will check:
- Python version compatibility
- All dependencies installed
- Browser drivers available
- .env file validity
- Locators file syntax
- Page objects importable
- Tests discoverable

### `doctor.py` - Framework Health Check (Planned for v7.0)
Diagnose common issues and suggest fixes.

```bash
python -m framework.cli.doctor
```

Will diagnose:
- Import errors
- Missing dependencies
- Outdated packages
- Configuration conflicts
- Permission issues
- WebDriver problems

### `init.py` - Project Initializer (Planned for v7.1)
Initialize new test project with structure.

```bash
python -m framework.cli.init my-test-project
```

Will create:
- Project directory structure
- Sample page objects
- Sample tests
- Configuration files
- Documentation

### `report.py` - Test Report Generator (Planned for v7.1)
Generate custom test reports.

```bash
python -m framework.cli.report \
    --format markdown \
    --input results/report.html \
    --output report.md
```

Will support:
- Multiple output formats (Markdown, PDF, HTML)
- Custom templates
- Charts and graphs
- Executive summaries

## Creating Custom CLI Tools

You can add your own CLI tools to this directory:

```python
# framework/cli/my_tool.py
#!/usr/bin/env python3
"""
My Custom Tool
Description of what it does.
"""

def main():
    """Main entry point."""
    print("My tool is running!")

if __name__ == "__main__":
    main()
```

**Run with:**
```bash
python -m framework.cli.my_tool
```

## Best Practices

1. **Use argparse** for command-line arguments
2. **Add --help** documentation
3. **Validate inputs** before processing
4. **Provide feedback** during execution
5. **Handle errors gracefully**
6. **Add to documentation** when stable

## Example: Using setup_wizard.py

```bash
# Navigate to project root
cd /path/to/project

# Run setup wizard
python -m framework.cli.setup_wizard

# Follow prompts:
# 1. Enter application URL
# 2. Choose browser (chrome/firefox/edge)
# 3. Configure headless mode
# 4. Set timeouts
# 5. Choose log level
# 6. (Optional) Configure advanced settings

# Result: .env file created with your settings
```

## Integration with IDE

### VS Code
Add to `.vscode/tasks.json`:
```json
{
    "label": "Setup Framework",
    "type": "shell",
    "command": "python -m framework.cli.setup_wizard"
}
```

### PyCharm
Add as External Tool:
- Program: `python`
- Arguments: `-m framework.cli.setup_wizard`
- Working directory: `$ProjectFileDir$`

## Troubleshooting

### Import Error: "No module named framework"
Ensure you're running from project root:
```bash
cd /path/to/project
python -m framework.cli.setup_wizard
```

### Permission Denied
Make script executable (Linux/Mac):
```bash
chmod +x framework/cli/setup_wizard.py
```

### Path Issues on Windows
Use forward slashes or raw strings:
```bash
python -m framework.cli.setup_wizard
```

## Contributing

To add a new CLI tool:

1. Create Python file in `framework/cli/`
2. Add shebang: `#!/usr/bin/env python3`
3. Add module docstring
4. Implement `main()` function
5. Add `if __name__ == "__main__": main()`
6. Update this README
7. Add tests in `tests/unit/framework/cli/`

---

For questions or suggestions, open an issue on GitHub.
