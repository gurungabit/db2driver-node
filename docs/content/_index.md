---
title: "db2-wire"
type: "home"
---

# db2-wire

**A zero-dependency DB2 driver for Node.js, built with pure Rust.**

db2-wire implements the IBM DRDA (Distributed Relational Database Architecture) wire protocol from scratch in Rust, exposed to Node.js via [napi-rs](https://napi.rs). No wrapping of `libpq`, `libdb2`, or any IBM CLI/ODBC library — we speak raw TCP to DB2.

## Why db2-wire?

- **Zero native dependencies** — No `libdb2`, `unixODBC`, or OpenSSL required
- **Pure Rust performance** — Direct DRDA wire protocol implementation
- **First-class Node.js support** — Native addon via napi-rs with full TypeScript types
- **Connection pooling** — Built-in async pool with health checks
- **TLS support** — Via rustls (pure Rust, no OpenSSL)

## Quick Example

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

const result = await client.query(
  'SELECT * FROM employees WHERE dept = ?',
  ['SALES']
);
console.log(result.rows);
// [{ ID: 1, NAME: 'Alice', DEPT: 'SALES' }, ...]

await client.close();
```

## Get Started

Head to the [Getting Started](/getting-started/) guide to install db2-wire and run your first query.
