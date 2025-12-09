# Database Utilities

## Overview

Database connection management and query execution utilities.

## Features

- Database connection pooling
- Query execution and validation
- Transaction management
- Data seeding and cleanup

## Usage

```python
from utils.database import DatabaseManager

db = DatabaseManager(connection_string)
result = db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,))
```
