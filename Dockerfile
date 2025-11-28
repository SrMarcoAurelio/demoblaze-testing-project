# Universal QA Automation Framework - Docker Image
# Python 3.11 base image with Selenium support
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies for Selenium
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create directories for test results and reports
RUN mkdir -p test_results allure-results allure-report

# Set proper permissions
RUN chmod -R 755 /app

# Default command: Run all tests with verbose output
CMD ["pytest", "tests/", "-v", "--html=test_results/report.html", "--self-contained-html"]
