---
title: "API Reference"
weight: 30
---

# API Reference

Complete TypeScript API reference for db2-wire.

## Types

### ConnectionConfig

```typescript
interface ConnectionConfig {
  host: string;
  port?: number;              // default: 50000
  database: string;
  user: string;
  password: string;
  ssl?: boolean | SslConfig;
  connectTimeout?: number;    // ms, default: 30000
  queryTimeout?: number;      // ms, default: 0 (no timeout)
  currentSchema?: string;
  fetchSize?: number;         // rows per fetch, default: 100
}
```

### SslConfig

```typescript
interface SslConfig {
  ca?: string;                // CA cert file path
  cert?: string;              // Client cert file path
  key?: string;               // Client key file path
  rejectUnauthorized?: boolean; // default: true
}
```

### PoolConfig

```typescript
interface PoolConfig extends ConnectionConfig {
  minConnections?: number;    // default: 0
  maxConnections?: number;    // default: 10
  idleTimeout?: number;       // ms, default: 60000
  maxLifetime?: number;       // ms, default: 3600000
}
```

### QueryResult

```typescript
interface QueryResult {
  rows: Record<string, any>[];
  rowCount: number;
  columns: ColumnInfo[];
}
```

### ColumnInfo

```typescript
interface ColumnInfo {
  name: string;
  type: string;
  nullable: boolean;
  precision?: number;
  scale?: number;
}
```

---

## Client

The `Client` class manages a single connection to a DB2 database.

### Constructor

```typescript
new Client(config: ConnectionConfig)
```

Creates a new client instance. Does not connect immediately — call `connect()` to establish the connection.

### client.connect()

```typescript
connect(): Promise<void>
```

Establishes a TCP connection to the DB2 server and performs the DRDA handshake (EXCSAT, ACCSEC, SECCHK, ACCRDB).

**Throws**: `Error` if connection fails (network error, authentication failure, database not found).

### client.query()

```typescript
query(sql: string, params?: any[]): Promise<QueryResult>
```

Executes a SQL statement and returns the result.

- For `SELECT` statements: returns rows in `result.rows`
- For `INSERT`/`UPDATE`/`DELETE`: returns affected row count in `result.rowCount`
- For `CREATE`/`DROP`/`ALTER`: returns empty result

**Parameters**:
- `sql` — SQL statement. Use `?` for parameter placeholders.
- `params` — Optional array of parameter values.

**Example**:
```typescript
// Simple query
const result = await client.query('SELECT * FROM employees');

// Parameterized query
const result = await client.query(
  'SELECT * FROM employees WHERE dept_id = ? AND salary > ?',
  [1, 100000]
);
```

### client.prepare()

```typescript
prepare(sql: string): Promise<PreparedStatement>
```

Prepares a SQL statement for repeated execution. Returns a `PreparedStatement` handle.

**Example**:
```typescript
const stmt = await client.prepare('INSERT INTO logs (msg) VALUES (?)');
await stmt.execute(['first message']);
await stmt.execute(['second message']);
await stmt.close();
```

### client.beginTransaction()

```typescript
beginTransaction(): Promise<Transaction>
```

Starts a new transaction. Returns a `Transaction` handle. The connection enters manual commit mode.

### client.close()

```typescript
close(): Promise<void>
```

Closes the connection to the DB2 server. The client cannot be reused after closing.

---

## Pool

The `Pool` class manages a pool of connections for concurrent access.

### Constructor

```typescript
new Pool(config: PoolConfig)
```

Creates a new connection pool. Connections are created lazily on demand.

### pool.query()

```typescript
query(sql: string, params?: any[]): Promise<QueryResult>
```

Acquires a connection from the pool, executes the query, and releases the connection back. This is the simplest way to run queries with pooling.

### pool.acquire()

```typescript
acquire(): Promise<Client>
```

Acquires a connection from the pool. The caller is responsible for releasing it with `pool.release()`.

### pool.release()

```typescript
release(client: Client): void
```

Returns a connection to the pool.

### pool.close()

```typescript
close(): Promise<void>
```

Closes all connections in the pool and prevents new acquisitions. Waits for all active connections to be released.

---

## PreparedStatement

A prepared SQL statement that can be executed multiple times with different parameters.

### stmt.execute()

```typescript
execute(params?: any[]): Promise<QueryResult>
```

Executes the prepared statement with the given parameters.

### stmt.close()

```typescript
close(): Promise<void>
```

Closes the prepared statement and releases server-side resources. Always close prepared statements when done.

---

## Transaction

A database transaction with manual commit/rollback control.

### tx.query()

```typescript
query(sql: string, params?: any[]): Promise<QueryResult>
```

Executes a SQL statement within the transaction.

### tx.commit()

```typescript
commit(): Promise<void>
```

Commits all changes made within the transaction.

### tx.rollback()

```typescript
rollback(): Promise<void>
```

Rolls back all changes made within the transaction.

---

## Type Mapping

| DB2 Type | JavaScript Type | Notes |
|----------|----------------|-------|
| `SMALLINT` | `number` | 16-bit integer |
| `INTEGER` | `number` | 32-bit integer |
| `BIGINT` | `bigint` | 64-bit integer |
| `REAL` | `number` | 32-bit float |
| `DOUBLE` | `number` | 64-bit float |
| `DECIMAL` | `string` | Preserves precision |
| `NUMERIC` | `string` | Preserves precision |
| `CHAR` | `string` | Fixed-length, right-trimmed |
| `VARCHAR` | `string` | Variable-length |
| `CLOB` | `string` | Character LOB |
| `BLOB` | `Buffer` | Binary LOB |
| `DATE` | `string` | `YYYY-MM-DD` format |
| `TIME` | `string` | `HH:MM:SS` format |
| `TIMESTAMP` | `string` | ISO 8601 format |
| `BOOLEAN` | `boolean` | |
| `XML` | `string` | XML as string |

### Parameter Type Inference

When passing parameters, JavaScript types are automatically mapped:

| JavaScript Type | DB2 Type |
|----------------|----------|
| `number` (integer) | `INTEGER` |
| `number` (float) | `DOUBLE` |
| `bigint` | `BIGINT` |
| `string` | `VARCHAR` |
| `boolean` | `BOOLEAN` |
| `null` / `undefined` | `NULL` |
| `Buffer` | `BLOB` |
| `Date` | `TIMESTAMP` |

---

## Error Handling

All async methods throw on failure. Errors include:

```typescript
try {
  await client.query('INVALID SQL');
} catch (err) {
  console.error(err.message);   // Human-readable error message
  console.error(err.sqlstate);  // SQLSTATE code (e.g., '42601')
  console.error(err.sqlcode);   // SQLCODE number
}
```

### Common SQLSTATE Codes

| SQLSTATE | Meaning |
|----------|---------|
| `08001` | Connection failure |
| `08004` | Server rejected connection |
| `28000` | Authentication failure |
| `42601` | SQL syntax error |
| `42704` | Object not found |
| `42710` | Object already exists |
| `23505` | Unique constraint violation |
| `40001` | Deadlock / serialization failure |
