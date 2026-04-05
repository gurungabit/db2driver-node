import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Client, Pool, type ConnectionConfig, type PoolConfig } from 'db2-wire';

function testConfig(): ConnectionConfig {
  return {
    host: process.env.DB2_TEST_HOST ?? 'localhost',
    port: Number(process.env.DB2_TEST_PORT ?? '50000'),
    database: process.env.DB2_TEST_DATABASE ?? 'testdb',
    user: process.env.DB2_TEST_USER ?? 'db2inst1',
    password: process.env.DB2_TEST_PASSWORD ?? 'db2wire_test_pw',
  };
}

function poolConfig(overrides?: Partial<PoolConfig>): PoolConfig {
  return {
    ...testConfig(),
    maxConnections: 5,
    ...overrides,
  };
}

describe('Client', () => {
  let client: Client;

  before(async () => {
    client = new Client(testConfig());
    await client.connect();
  });

  after(async () => {
    await client.close();
  });

  it('should connect and execute a simple query', async () => {
    const result = await client.query('VALUES 1');
    assert.equal(result.rowCount, 1);
    assert.equal(result.rows.length, 1);
  });

  it('should return column metadata', async () => {
    const result = await client.query('VALUES (1, \'hello\', 3.14)');
    assert.ok(result.columns.length >= 3, 'should have at least 3 columns');
    for (const col of result.columns) {
      assert.ok(typeof col.name === 'string', 'column name should be a string');
      assert.ok(typeof col.type === 'string', 'column type should be a string');
      assert.ok(typeof col.nullable === 'boolean', 'nullable should be a boolean');
    }
  });

  it('should handle parameterized queries', async () => {
    const result = await client.query('VALUES (?, ?, ?)', [42, 'hello', null]);
    assert.equal(result.rowCount, 1);
    assert.equal(result.rows.length, 1);
  });

  it('should return empty result set', async () => {
    // Use SYSIBM.SYSDUMMY1 with an impossible condition
    const result = await client.query(
      'SELECT * FROM SYSIBM.SYSDUMMY1 WHERE 1 = 0'
    );
    assert.equal(result.rows.length, 0);
    assert.equal(result.rowCount, 0);
    assert.ok(result.columns.length >= 1, 'should still have column metadata');
  });

  it('should return rowCount for INSERT', async () => {
    const table = `tmp_nodeins_${Date.now() % 1000000}`;
    try {
      await client.query(`CREATE TABLE ${table} (id INTEGER, val VARCHAR(50))`);
      const result = await client.query(
        `INSERT INTO ${table} VALUES (1, 'a'), (2, 'b'), (3, 'c')`
      );
      assert.equal(result.rowCount, 3, 'should report 3 rows inserted');
    } finally {
      await client.query(`DROP TABLE ${table}`).catch(() => {});
    }
  });

  it('should reject bad SQL with an error', async () => {
    await assert.rejects(
      () => client.query('SELCT * FORM nosuchtable'),
      (err: Error) => {
        assert.ok(err.message.length > 0, 'error should have a message');
        return true;
      }
    );
  });
});

describe('Pool', () => {
  let pool: Pool;

  before(() => {
    pool = new Pool(poolConfig());
  });

  after(async () => {
    await pool.close();
  });

  it('should execute a query through the pool', async () => {
    const result = await pool.query('VALUES 1');
    assert.equal(result.rowCount, 1);
  });

  it('should handle concurrent queries', async () => {
    const promises = Array.from({ length: 20 }, (_, i) =>
      pool.query(`VALUES ${i}`)
    );
    const results = await Promise.all(promises);
    assert.equal(results.length, 20);
    for (const r of results) {
      assert.equal(r.rowCount, 1);
    }
  });
});

describe('Transaction', () => {
  let client: Client;

  before(async () => {
    client = new Client(testConfig());
    await client.connect();
  });

  after(async () => {
    await client.close();
  });

  it('should commit a transaction', async () => {
    const table = `tmp_nodetxc_${Date.now() % 1000000}`;
    try {
      await client.query(`CREATE TABLE ${table} (id INTEGER)`);
      const txn = await client.beginTransaction();
      await txn.query(`INSERT INTO ${table} VALUES (1)`);
      await txn.commit();

      const result = await client.query(`SELECT * FROM ${table}`);
      assert.equal(result.rows.length, 1, 'committed row should be visible');
    } finally {
      await client.query(`DROP TABLE ${table}`).catch(() => {});
    }
  });

  it('should rollback a transaction', async () => {
    const table = `tmp_nodetxr_${Date.now() % 1000000}`;
    try {
      await client.query(`CREATE TABLE ${table} (id INTEGER)`);
      await client.query(`INSERT INTO ${table} VALUES (1)`);

      const txn = await client.beginTransaction();
      await txn.query(`INSERT INTO ${table} VALUES (2)`);
      await txn.rollback();

      const result = await client.query(`SELECT * FROM ${table}`);
      assert.equal(
        result.rows.length,
        1,
        'rolled-back row should not be visible'
      );
    } finally {
      await client.query(`DROP TABLE ${table}`).catch(() => {});
    }
  });
});
