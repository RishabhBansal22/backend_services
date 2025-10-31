# GitHub Actions Workflow for Tests

This repository uses GitHub Actions to automatically run tests on every push to `main` and on all pull requests targeting `main`.

## Workflow Details

### Triggers
- **Push to main**: Tests run whenever code is merged or pushed to the main branch
- **Pull Requests**: Tests run on all PRs targeting main to ensure code quality before merging

### What Gets Tested
- All unit tests in `auth/tests/`
- Test coverage analysis
- Python 3.10 on Ubuntu (latest)

### Workflow Steps
1. **Checkout code**: Gets the latest code from the repository
2. **Set up Python**: Installs Python 3.10
3. **Install uv**: Installs the uv package manager
4. **Install dependencies**: Runs `uv sync` to install all project dependencies
5. **Run tests**: Executes pytest with coverage reporting
6. **Upload coverage**: Saves coverage report as an artifact

## Viewing Test Results

### On GitHub
1. Go to your repository on GitHub
2. Click on the "Actions" tab
3. Select the workflow run you want to view
4. Click on the "test" job to see detailed test output

### Pull Request Status
- ✅ Green checkmark: All tests passed
- ❌ Red X: Tests failed (PR cannot be merged until fixed)
- 🟡 Yellow circle: Tests are running

## Local Testing Before Push

Always run tests locally before pushing:

```bash
# Run all tests
pytest auth/tests/ -v

# Run with coverage
pytest auth/tests/ -v --cov=auth --cov-report=term-missing
```

## Troubleshooting

### If tests fail in CI but pass locally:
- Check Python version (CI uses 3.10)
- Ensure all dependencies are in `pyproject.toml`
- Check for environment-specific issues

### Viewing detailed logs:
- Click on the failed workflow run in GitHub Actions
- Expand the "Run tests with pytest" step
- Review the error messages and stack traces
