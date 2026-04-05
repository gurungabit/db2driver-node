export interface ConnectionConfig {
  host: string;
  port?: number;
  database: string;
  user: string;
  password: string;
  ssl?: boolean | SslConfig;
  connectTimeout?: number;
  queryTimeout?: number;
  currentSchema?: string;
  fetchSize?: number;
}

export interface SslConfig {
  ca?: string;
  cert?: string;
  key?: string;
  rejectUnauthorized?: boolean;
}

export interface PoolConfig extends ConnectionConfig {
  minConnections?: number;
  maxConnections?: number;
  idleTimeout?: number;
  maxLifetime?: number;
}

export interface QueryResult {
  rows: Record<string, any>[];
  rowCount: number;
  columns: ColumnInfo[];
}

export interface ColumnInfo {
  name: string;
  type: string;
  nullable: boolean;
  precision?: number;
  scale?: number;
}

export class Client {
  constructor(config: ConnectionConfig);
  connect(): Promise<void>;
  query(sql: string, params?: any[]): Promise<QueryResult>;
  prepare(sql: string): Promise<PreparedStatement>;
  beginTransaction(): Promise<Transaction>;
  close(): Promise<void>;
  serverInfo(): { productName: string; serverRelease: string };
}

export class Pool {
  constructor(config: PoolConfig);
  query(sql: string, params?: any[]): Promise<QueryResult>;
  acquire(): Promise<Client>;
  release(client: Client): void;
  close(): Promise<void>;
}

export class PreparedStatement {
  execute(params?: any[]): Promise<QueryResult>;
  close(): Promise<void>;
}

export class Transaction {
  query(sql: string, params?: any[]): Promise<QueryResult>;
  commit(): Promise<void>;
  rollback(): Promise<void>;
}
