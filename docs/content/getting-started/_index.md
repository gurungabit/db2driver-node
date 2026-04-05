---
title: "Getting Started"
weight: 10
---

# Getting Started

This guide walks you through installing db2-wire, connecting to a DB2 database, and running your first queries.

## Prerequisites

- **Node.js** 18 or later
- **DB2** instance (local or remote) — see [Development Setup](#development-setup) for Docker instructions

## Installation

```bash
npm install db2-wire
```

db2-wire ships prebuilt native binaries for:
- `linux-x64` (glibc)
- `darwin-arm64` (Apple Silicon)
- `win32-x64`

No compiler toolchain needed for supported platforms.

## Connecting to DB2

```typescript
import { Client } from 'db2-wire';

const client = new Client({
  host: 'localhost',
  port: 50000,
  database: 'MYDB',
  user: 'db2inst1',
  password: 'password',
});

await client.connect();
```

### Connection Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | `string` | — | DB2 server hostname |
| `port` | `number` | `50000` | DB2 server port |
| `database` | `string` | — | Database name |
| `user` | `string` | — | Username |
| `password` | `string` | — | Password |
| `ssl` | `boolean \| SslConfig` | `false` | Enable TLS |
| `connectTimeout` | `number` | `30000` | Connection timeout in ms |
| `queryTimeout` | `number` | `0` | Query timeout in ms (0 = none) |
| `currentSchema` | `string` | — | Default schema |
| `fetchSize` | `number` | `100` | Rows per fetch batch |

## Running Queries

### Simple Queries

```typescript
const result = await client.query('SELECT * FROM employees');
console.log(result.rows);    // Array of row objects
console.log(result.rowCount); // Number of rows
console.log(result.columns);  // Column metadata
```

### Parameterized Queries

Always use parameterized queries to prevent SQL injection:

```typescript
const result = await client.query(
  'SELECT name, salary FROM employees WHERE dept_id = ? AND active = ?',
  [1, true]
);
```

### INSERT / UPDATE / DELETE

```typescript
const result = await client.query(
  'INSERT INTO employees (name, dept_id) VALUES (?, ?)',
  ['Alice', 1]
);
console.log(result.rowCount); // 1
```

## Prepared Statements

For queries executed multiple times with different parameters:

```typescript
const stmt = await client.prepare(
  'INSERT INTO employees (name, dept_id) VALUES (?, ?)'
);

await stmt.execute(['Alice', 1]);
await stmt.execute(['Bob', 2]);
await stmt.execute(['Carol', 1]);

await stmt.close();
```

## Transactions

```typescript
const tx = await client.beginTransaction();

try {
  await tx.query('UPDATE accounts SET balance = balance - 100 WHERE id = ?', [1]);
  await tx.query('UPDATE accounts SET balance = balance + 100 WHERE id = ?', [2]);
  await tx.commit();
} catch (e) {
  await tx.rollback();
  throw e;
}
```

## Connection Pool

For applications with concurrent database access:

```typescript
import { Pool } from 'db2-wire';

const pool = new Pool({
  host: 'localhost',
  port: 50000,
  database: 'MYDB',
  user: 'db2inst1',
  password: 'password',
  maxConnections: 20,
  idleTimeout: 30000,
});

// Pool manages connections automatically
const result = await pool.query('SELECT COUNT(*) AS cnt FROM employees');

// Or acquire a connection for multiple operations
const client = await pool.acquire();
// ... use client ...
pool.release(client);

await pool.close();
```

## TLS / SSL

```typescript
const client = new Client({
  host: 'db2.example.com',
  port: 50001,
  database: 'PRODDB',
  user: 'app_user',
  password: 'secret',
  ssl: {
    ca: '/path/to/ca-cert.pem',
    rejectUnauthorized: true,
  },
});
```

## Development Setup

To run a local DB2 instance for development and testing:

```bash
# Clone the repository
git clone https://github.com/gurungabit/db2driver-node.git
cd db2driver-node

# Start DB2 in Docker (takes 2-5 min on first run)
./tools/db2.sh start

# DB2 is now running at localhost:50000
# Database: testdb
# User: db2inst1
# Password: db2wire_test_pw
```

See the [Contributing](/contributing/) guide for full development instructions.
