import { Client } from "@gurungabit/db2-node";

let client: Client | null = null;
let initialized = false;

const config = {
  host: process.env.DB2_HOST || "localhost",
  port: Number(process.env.DB2_PORT) || 50000,
  database: process.env.DB2_DATABASE || "testdb",
  user: process.env.DB2_USER || "db2inst1",
  password: process.env.DB2_PASSWORD || "db2wire_test_pw",
};

export async function getClient() {
  if (!client) {
    client = new Client(config);
    await client.connect();
  }

  if (!initialized) {
    initialized = true;
    await ensureTable();
  }

  return client;
}

async function ensureTable() {
  const check = await client!.query(
    `SELECT 1 FROM SYSCAT.TABLES WHERE TABNAME = 'TODOS' AND TABSCHEMA = CURRENT SCHEMA`,
  );
  if (check.rows.length === 0) {
    await client!.query(`
      CREATE TABLE todos (
        id         INT NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        title      VARCHAR(255) NOT NULL,
        completed  SMALLINT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT TIMESTAMP
      )
    `);
  }
}
