# Pre-commit Hooks - Automated Code Quality

## 🎯 Overview

This project uses [pre-commit](https://pre-commit.com/) to automatically enforce code quality standards before each commit. This ensures that all code meets our quality standards without manual checks.

## ✅ Hooks Enabled

### 1. **General File Checks**
- ✅ Check for large files (max 1000KB)
- ✅ Check for case conflicts
- ✅ Check for merge conflicts
- ✅ Validate YAML/JSON syntax
- ✅ Fix end-of-file newlines
- ✅ Remove trailing whitespace
- ✅ Detect debugger statements
- ✅ Detect private keys
- ✅ Fix mixed line endings (LF)

### 2. **Python Code Formatting**
- **Black**: Auto-formats Python code (line length: 79)
- **isort**: Sorts imports alphabetically

###3. **Python Code Quality**
- **Flake8**: Linting and style checking
  - Max line length: 100
  - Relaxed rules for test files

### 4. **Type Checking**
- **Mypy**: Static type checking
  - Strict mode enabled
  - Checks: `pages/`, `utils/helpers/`

## 📦 Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install
```

## 🚀 Usage

### Automatic (on git commit)
Pre-commit hooks run automatically when you commit:

```bash
git add .
git commit -m "Your commit message"

# Hooks will run automatically:
# ✓ If all pass → commit succeeds
# ✗ If any fail → commit blocked, files auto-fixed
```

### Manual (run on all files)
```bash
# Run on all files
pre-commit run --all-files

# Run specific hook
pre-commit run black --all-files
pre-commit run mypy --all-files
```

### Bypass (not recommended)
```bash
# Skip hooks (emergency only!)
git commit --no-verify -m "Emergency fix"
```

## 🔧 Configuration

Configuration in `.pre-commit-config.yaml`:

```yaml
# Update hooks to latest versions
pre-commit autoupdate

# See all available hooks
pre-commit run --all-files --verbose
```

## 📝 What Gets Checked

| Hook | What It Does | Auto-Fix |
|------|--------------|----------|
| **black** | Reformats Python code | ✅ Yes |
| **isort** | Sorts imports | ✅ Yes |
| **flake8** | Checks code style | ❌ No |
| **mypy** | Type checking | ❌ No |
| **trailing-whitespace** | Removes trailing spaces | ✅ Yes |
| **end-of-file-fixer** | Adds final newline | ✅ Yes |

## ⚡ Performance

- **First run**: ~2-3 minutes (installs environments)
- **Subsequent runs**: ~5-10 seconds
- Environments are cached and reused

## 🎓 Best Practices

### DO:
✅ Run `pre-commit run --all-files` after pulling changes
✅ Let hooks auto-fix files, then review and commit
✅ Fix mypy/flake8 errors before committing
✅ Keep `.pre-commit-config.yaml` updated

### DON'T:
❌ Use `--no-verify` unless absolutely necessary
❌ Ignore hook failures
❌ Commit with unresolved type errors

## 🐛 Troubleshooting

### Hooks fail with "command not found"
```bash
# Reinstall pre-commit
pip install --upgrade pre-commit
pre-commit clean
pre-commit install
```

### Hooks take too long
```bash
# Clear cache and reinstall
pre-commit clean
pre-commit install --install-hooks
```

### Skip specific files
Add to `.pre-commit-config.yaml`:
```yaml
exclude: '^(path/to/skip/|another/path/)'
```

## 📊 Current Quality Standards

- **Black**: line-length=79
- **Flake8**: max-line-length=100, relaxed for tests
- **Mypy**: strict mode, 100% type coverage
- **isort**: black-compatible profile

## 🔄 Updating Hooks

```bash
# Update all hooks to latest versions
pre-commit autoupdate

# Test updated hooks
pre-commit run --all-files
```

---

**Questions?** Check the [pre-commit documentation](https://pre-commit.com/)
