# Test Data Utilities

## Overview

Test data generation, management, and cleanup utilities.

## Features

- Fake data generation (users, products, orders)
- Database seeding
- Data factory patterns
- JSON/CSV data loading
- Test data cleanup

## Usage

```python
from utils.test_data import DataFactory, DataSeeder

# Generate fake user
factory = DataFactory()
user = factory.create_user()

# Seed database
seeder = DataSeeder(db_connection)
seeder.seed_users(count=10)
```
