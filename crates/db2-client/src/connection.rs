use bytes::BytesMut;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, trace};

use crate::auth::{self, ServerInfo};
use crate::column::ColumnInfo;
use crate::config::Config;
use crate::cursor::Cursor;
use crate::error::Error;
use crate::row::Row;
use crate::transport::Transport;
use crate::types::{self, QueryResult, ToSql};
use db2_proto::codepoints;
use db2_proto::ddm::DdmObject;
use db2_proto::dss::{DssFrame, DssReader, DssWriter};

/// Internal shared state for a DB2 connection.
pub(crate) struct ClientInner {
    pub transport: Option<Transport>,
    pub config: Config,
    pub server_info: Option<ServerInfo>,
    pub correlation_id: u16,
    pub section_number: u16,
    pub connected: bool,
    pub recv_buf: BytesMut,
}

impl ClientInner {
    /// Get the next correlation ID.
    pub fn next_correlation_id(&mut self) -> u16 {
        let id = self.correlation_id;
        self.correlation_id = self.correlation_id.wrapping_add(1);
        if self.correlation_id == 0 {
            self.correlation_id = 1;
        }
        id
    }

    /// Get the next section number for prepared statements.
    pub fn next_section_number(&mut self) -> u16 {
        let sn = self.section_number;
        self.section_number = self.section_number.wrapping_add(1);
        if self.section_number == 0 {
            self.section_number = 1;
        }
        sn
    }

    /// Send raw bytes over the transport.
    pub async fn send_bytes(&mut self, data: &[u8]) -> Result<(), Error> {
        let transport = self
            .transport
            .as_mut()
            .ok_or_else(|| Error::Connection("Transport not initialized".into()))?;
        transport.write_bytes(data).await
    }

    /// Read DSS frames from the transport, waiting for at least `min_frames` frames.
    pub async fn read_frames(&mut self, min_frames: usize) -> Result<Vec<DssFrame>, Error> {
        let transport = self
            .transport
            .as_mut()
            .ok_or_else(|| Error::Connection("Transport not initialized".into()))?;

        // Ensure we have enough data
        if self.recv_buf.len() < 6 {
            transport.read_at_least(&mut self.recv_buf, 6).await?;
        }

        loop {
            let mut reader = DssReader::new(self.recv_buf.to_vec());
            let frames = reader
                .read_all_frames()
                .map_err(|e| Error::Protocol(e.to_string()))?;
            if frames.len() >= min_frames {
                let remaining = reader.into_remaining();
                self.recv_buf = BytesMut::from(remaining.as_slice());
                return Ok(frames);
            }
            transport.read_bytes(&mut self.recv_buf).await?;
        }
    }

    /// Read all available DSS frames (at least 1).
    pub async fn read_reply_frames(&mut self) -> Result<Vec<DssFrame>, Error> {
        self.read_frames(1).await
    }

    /// Parse a DDM object from a DSS frame payload.
    pub fn parse_ddm(payload: &[u8]) -> Result<DdmObject, Error> {
        let (obj, _) = DdmObject::parse(payload).map_err(|e| Error::Protocol(e.to_string()))?;
        Ok(obj)
    }

    /// Execute an SQL statement immediately (no parameters).
    pub async fn execute_immediate(&mut self, sql: &str) -> Result<QueryResult, Error> {
        debug!("Execute immediate: {}", sql);

        let corr_id = self.next_correlation_id();
        let section_number = self.next_section_number();

        // Build PKGNAMCSN and commands
        let pkgnamcsn =
            db2_proto::commands::build_default_pkgnamcsn(&self.config.database, section_number);
        let excsqlimm_data = db2_proto::commands::excsqlimm::build_excsqlimm_default(&pkgnamcsn);
        let sqlstt_data = db2_proto::commands::sqlstt::build_sqlstt(sql);

        // Wrap in DSS: EXCSQLIMM (Request, chained) + SQLSTT (Object, not chained)
        let mut writer = DssWriter::new(corr_id);
        writer.write_request(&excsqlimm_data, true);
        writer.write_object(&sqlstt_data, false);

        let send_buf = writer.finish();
        self.send_bytes(&send_buf).await?;

        // Read reply frames
        let frames = self.read_reply_frames().await?;
        self.process_execute_reply(&frames).await
    }

    /// Execute a query with parameters.
    pub async fn execute_query(
        &mut self,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Result<QueryResult, Error> {
        if params.is_empty() {
            return self.execute_immediate(sql).await;
        }

        debug!("Execute query with {} params: {}", params.len(), sql);

        let section_number = self.next_section_number();

        // Step 1: Prepare the statement (PRPSQLSTT + SQLSTT)
        let corr_id = self.next_correlation_id();
        let pkgnamcsn =
            db2_proto::commands::build_default_pkgnamcsn(&self.config.database, section_number);
        let prpsqlstt_data = db2_proto::commands::prpsqlstt::build_prpsqlstt_with_sqlda(&pkgnamcsn);
        let sqlstt_data = db2_proto::commands::sqlstt::build_sqlstt(sql);

        let mut writer = DssWriter::new(corr_id);
        writer.write_request(&prpsqlstt_data, true);
        writer.write_object(&sqlstt_data, false);

        let send_buf = writer.finish();
        self.send_bytes(&send_buf).await?;

        let frames = self.read_reply_frames().await?;
        let column_info = self.parse_prepare_reply(&frames)?;

        // Step 2: Execute with parameters
        let is_query = sql_is_query(sql);

        if is_query {
            self.execute_open_query(&pkgnamcsn, params, &column_info)
                .await
        } else {
            self.execute_with_params(&pkgnamcsn, params).await
        }
    }

    /// Open a query (SELECT) with parameters.
    async fn execute_open_query(
        &mut self,
        pkgnamcsn: &[u8],
        params: &[&dyn ToSql],
        column_info: &[ColumnInfo],
    ) -> Result<QueryResult, Error> {
        let corr_id = self.next_correlation_id();
        let opnqry_data = db2_proto::commands::opnqry::build_opnqry(
            pkgnamcsn,
            db2_proto::commands::opnqry::DEFAULT_QRYBLKSZ,
            Some(-1),
            codepoints::QRYPRCTYP_LMTBLKPRC,
            Some(self.config.fetch_size),
            None,
        );
        let sqldta_data = build_sqldta(params);

        let mut writer = DssWriter::new(corr_id);
        writer.write_request(&opnqry_data, true);
        writer.write_object(&sqldta_data, false);

        let send_buf = writer.finish();
        self.send_bytes(&send_buf).await?;

        let frames = self.read_reply_frames().await?;
        self.process_query_reply(&frames, column_info).await
    }

    /// Execute a DML statement with parameters.
    async fn execute_with_params(
        &mut self,
        pkgnamcsn: &[u8],
        params: &[&dyn ToSql],
    ) -> Result<QueryResult, Error> {
        let corr_id = self.next_correlation_id();
        let excsqlstt_data = db2_proto::commands::excsqlstt::build_excsqlstt_default(pkgnamcsn);
        let sqldta_data = build_sqldta(params);

        let mut writer = DssWriter::new(corr_id);
        writer.write_request(&excsqlstt_data, true);
        writer.write_object(&sqldta_data, false);

        let send_buf = writer.finish();
        self.send_bytes(&send_buf).await?;

        let frames = self.read_reply_frames().await?;
        self.process_execute_reply(&frames).await
    }

    /// Public wrapper for process_query_reply (used by PreparedStatement).
    pub async fn process_query_reply_public(
        &mut self,
        frames: &[DssFrame],
        column_info: &[ColumnInfo],
    ) -> Result<QueryResult, Error> {
        self.process_query_reply(frames, column_info).await
    }

    /// Public wrapper for process_execute_reply (used by PreparedStatement).
    pub async fn process_execute_reply_public(
        &mut self,
        frames: &[DssFrame],
    ) -> Result<QueryResult, Error> {
        self.process_execute_reply(frames).await
    }

    /// Process reply frames from a query that returns rows.
    async fn process_query_reply(
        &mut self,
        frames: &[DssFrame],
        column_info: &[ColumnInfo],
    ) -> Result<QueryResult, Error> {
        let mut rows = Vec::new();
        let mut qrydsc_descriptors: Option<Vec<db2_proto::fdoca::ColumnDescriptor>> = None;
        let mut end_of_query = false;

        for frame in frames {
            let obj = Self::parse_ddm(&frame.payload)?;

            match obj.code_point {
                codepoints::OPNQRYRM => {
                    trace!("Received OPNQRYRM");
                    let reply = db2_proto::replies::opnqryrm::parse_opnqryrm(&obj)
                        .map_err(|e| Error::Protocol(e.to_string()))?;
                    if !reply.is_success() {
                        return Err(Error::Sql {
                            sqlstate: "HY000".into(),
                            sqlcode: -(reply.severity_code as i32),
                            message: "Open query failed".into(),
                        });
                    }
                }
                codepoints::QRYDSC => {
                    trace!("Received QRYDSC");
                    let descriptors = db2_proto::fdoca::parse_qrydsc(&obj.data)
                        .map_err(|e| Error::Protocol(e.to_string()))?;
                    qrydsc_descriptors = Some(descriptors);
                }
                codepoints::QRYDTA => {
                    trace!("Received QRYDTA");
                    if let Some(ref descs) = qrydsc_descriptors {
                        let decoded_rows = db2_proto::fdoca::decode_rows(&obj.data, descs)
                            .map_err(|e| Error::Protocol(e.to_string()))?;
                        for values in decoded_rows {
                            let col_names: Vec<String> =
                                column_info.iter().map(|c| c.name.clone()).collect();
                            rows.push(Row::new(col_names, values));
                        }
                    }
                }
                codepoints::ENDQRYRM => {
                    trace!("Received ENDQRYRM");
                    end_of_query = true;
                }
                codepoints::SQLCARD => {
                    trace!("Received SQLCARD in query reply");
                }
                _ => {
                    trace!("Ignoring reply codepoint 0x{:04X}", obj.code_point);
                }
            }
        }

        // If not end of query, continue fetching
        if !end_of_query {
            if let Some(descriptors) = qrydsc_descriptors {
                let mut cursor =
                    Cursor::new(column_info.to_vec(), descriptors, self.config.fetch_size);

                loop {
                    let (more_rows, done) = cursor.fetch_next_from(self).await?;
                    rows.extend(more_rows);
                    if done {
                        break;
                    }
                }
            }
        }

        Ok(QueryResult::with_rows(rows, column_info.to_vec()))
    }

    /// Process reply frames from an execute (non-query) statement.
    async fn process_execute_reply(&mut self, frames: &[DssFrame]) -> Result<QueryResult, Error> {
        let mut row_count: i64 = 0;
        let mut columns = Vec::new();

        for frame in frames {
            let obj = Self::parse_ddm(&frame.payload)?;

            match obj.code_point {
                codepoints::SQLCARD => {
                    trace!("Received SQLCARD");
                    let card = db2_proto::replies::sqlcard::parse_sqlcard(&obj)
                        .map_err(|e| Error::Protocol(e.to_string()))?;

                    if card.is_error() {
                        return Err(Error::Sql {
                            sqlstate: card.sqlstate,
                            sqlcode: card.sqlcode,
                            message: if card.sqlerrmc.is_empty() {
                                format!("SQL error: SQLCODE={}", card.sqlcode)
                            } else {
                                card.sqlerrmc
                            },
                        });
                    }
                    row_count = card.row_count() as i64;
                }
                codepoints::RDBUPDRM => {
                    trace!("Received RDBUPDRM");
                }
                codepoints::SQLERRRM => {
                    trace!("Received SQLERRRM");
                    return Err(Error::Sql {
                        sqlstate: "HY000".into(),
                        sqlcode: -1,
                        message: "SQL error reply received".into(),
                    });
                }
                codepoints::SQLDARD => {
                    trace!("Received SQLDARD");
                    columns = parse_sqldard_columns(&obj);
                }
                codepoints::ENDQRYRM => {
                    trace!("Received ENDQRYRM");
                }
                _ => {
                    trace!("Ignoring reply codepoint 0x{:04X}", obj.code_point);
                }
            }
        }

        Ok(QueryResult {
            rows: Vec::new(),
            row_count,
            columns,
        })
    }

    /// Parse the reply to a PRPSQLSTT (prepare) command.
    pub fn parse_prepare_reply(&self, frames: &[DssFrame]) -> Result<Vec<ColumnInfo>, Error> {
        let mut columns = Vec::new();

        for frame in frames {
            let obj = Self::parse_ddm(&frame.payload)?;

            match obj.code_point {
                codepoints::SQLDARD => {
                    trace!("Received SQLDARD from prepare");
                    columns = parse_sqldard_columns(&obj);
                }
                codepoints::SQLCARD => {
                    let card = db2_proto::replies::sqlcard::parse_sqlcard(&obj)
                        .map_err(|e| Error::Protocol(e.to_string()))?;
                    if card.is_error() {
                        return Err(Error::Sql {
                            sqlstate: card.sqlstate,
                            sqlcode: card.sqlcode,
                            message: format!("Prepare failed: {}", card.sqlerrmc),
                        });
                    }
                }
                _ => {
                    trace!("Prepare reply: ignoring 0x{:04X}", obj.code_point);
                }
            }
        }

        Ok(columns)
    }

    /// Send RDBCMM (commit) command.
    pub async fn commit(&mut self) -> Result<(), Error> {
        debug!("Sending RDBCMM (commit)");
        let corr_id = self.next_correlation_id();
        let rdbcmm_data = db2_proto::commands::rdbcmm::build_rdbcmm();

        let mut writer = DssWriter::new(corr_id);
        writer.write_request(&rdbcmm_data, false);
        let send_buf = writer.finish();
        self.send_bytes(&send_buf).await?;

        let frames = self.read_reply_frames().await?;
        for frame in &frames {
            let obj = Self::parse_ddm(&frame.payload)?;
            if obj.code_point == codepoints::SQLCARD {
                let card = db2_proto::replies::sqlcard::parse_sqlcard(&obj)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                if card.is_error() {
                    return Err(Error::Sql {
                        sqlstate: card.sqlstate,
                        sqlcode: card.sqlcode,
                        message: format!("Commit failed: {}", card.sqlerrmc),
                    });
                }
            }
        }

        debug!("Commit successful");
        Ok(())
    }

    /// Send RDBRLLBCK (rollback) command.
    pub async fn rollback(&mut self) -> Result<(), Error> {
        debug!("Sending RDBRLLBCK (rollback)");
        let corr_id = self.next_correlation_id();
        let rdbrllbck_data = db2_proto::commands::rdbrllbck::build_rdbrllbck();

        let mut writer = DssWriter::new(corr_id);
        writer.write_request(&rdbrllbck_data, false);
        let send_buf = writer.finish();
        self.send_bytes(&send_buf).await?;

        let frames = self.read_reply_frames().await?;
        for frame in &frames {
            let obj = Self::parse_ddm(&frame.payload)?;
            if obj.code_point == codepoints::SQLCARD {
                let card = db2_proto::replies::sqlcard::parse_sqlcard(&obj)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                if card.is_error() {
                    return Err(Error::Sql {
                        sqlstate: card.sqlstate,
                        sqlcode: card.sqlcode,
                        message: format!("Rollback failed: {}", card.sqlerrmc),
                    });
                }
            }
        }

        debug!("Rollback successful");
        Ok(())
    }
}

/// The main DB2 client. Wraps shared internal state in an Arc<Mutex<>>.
pub struct Client {
    pub(crate) inner: Arc<Mutex<ClientInner>>,
}

impl Client {
    /// Create a new Client with the given configuration. Does not connect immediately.
    pub fn new(config: Config) -> Self {
        Client {
            inner: Arc::new(Mutex::new(ClientInner {
                transport: None,
                config,
                server_info: None,
                correlation_id: 1,
                section_number: 1,
                connected: false,
                recv_buf: BytesMut::with_capacity(8192),
            })),
        }
    }

    /// Connect to the DB2 server, performing TLS upgrade and DRDA authentication.
    pub async fn connect(&mut self) -> Result<(), Error> {
        let config = {
            let guard = self.inner.lock().await;
            guard.config.clone()
        };

        // Establish transport
        let mut transport = Transport::connect(&config).await?;

        // Perform DRDA authentication handshake
        let (server_info, next_corr_id) = auth::authenticate(&mut transport, &config).await?;

        // Store the connected state
        let mut guard = self.inner.lock().await;
        guard.transport = Some(transport);
        guard.server_info = Some(server_info);
        guard.correlation_id = next_corr_id;
        guard.connected = true;

        debug!("Client connected to DB2 server");
        Ok(())
    }

    /// Create a new client and immediately connect.
    pub async fn connect_with(config: Config) -> Result<Self, Error> {
        let mut client = Client::new(config);
        client.connect().await?;
        Ok(client)
    }

    /// Execute a SQL query or statement with optional parameters.
    pub async fn query(&self, sql: &str, params: &[&dyn ToSql]) -> Result<QueryResult, Error> {
        let mut guard = self.inner.lock().await;
        if !guard.connected {
            return Err(Error::Connection("Not connected".into()));
        }
        guard.execute_query(sql, params).await
    }

    /// Execute a SQL statement with no parameters.
    pub async fn execute(&self, sql: &str) -> Result<QueryResult, Error> {
        self.query(sql, &[]).await
    }

    /// Prepare a SQL statement for later execution with parameters.
    pub async fn prepare(&self, sql: &str) -> Result<crate::statement::PreparedStatement, Error> {
        let mut guard = self.inner.lock().await;
        if !guard.connected {
            return Err(Error::Connection("Not connected".into()));
        }

        let section_number = guard.next_section_number();
        let corr_id = guard.next_correlation_id();
        let pkgnamcsn =
            db2_proto::commands::build_default_pkgnamcsn(&guard.config.database, section_number);

        // Send PRPSQLSTT + SQLSTT
        let prpsqlstt_data = db2_proto::commands::prpsqlstt::build_prpsqlstt_with_sqlda(&pkgnamcsn);
        let sqlstt_data = db2_proto::commands::sqlstt::build_sqlstt(sql);

        let mut writer = DssWriter::new(corr_id);
        writer.write_request(&prpsqlstt_data, true);
        writer.write_object(&sqlstt_data, false);

        let send_buf = writer.finish();
        guard.send_bytes(&send_buf).await?;

        let frames = guard.read_reply_frames().await?;
        let column_metadata = guard.parse_prepare_reply(&frames)?;

        drop(guard);

        Ok(crate::statement::PreparedStatement::new(
            self.inner.clone(),
            sql.to_string(),
            section_number,
            column_metadata,
        ))
    }

    /// Begin a new transaction (turns off auto-commit behavior).
    pub async fn begin_transaction(&self) -> Result<crate::transaction::Transaction, Error> {
        let guard = self.inner.lock().await;
        if !guard.connected {
            return Err(Error::Connection("Not connected".into()));
        }
        drop(guard);

        Ok(crate::transaction::Transaction::new(self.inner.clone()))
    }

    /// Close the connection.
    pub async fn close(&self) -> Result<(), Error> {
        let mut guard = self.inner.lock().await;
        if guard.connected {
            guard.connected = false;
            if let Some(transport) = guard.transport.as_mut() {
                transport.close().await?;
            }
            debug!("Connection closed");
        }
        Ok(())
    }

    /// Get the server info (populated after connect).
    pub async fn server_info(&self) -> Option<ServerInfo> {
        let guard = self.inner.lock().await;
        guard.server_info.clone()
    }

    /// Check if the client is connected.
    pub async fn is_connected(&self) -> bool {
        let guard = self.inner.lock().await;
        guard.connected
    }
}

// ============================================================
// Helper functions
// ============================================================

/// Build SQLDTA (SQL Data) DDM object for parameters.
fn build_sqldta(params: &[&dyn ToSql]) -> Vec<u8> {
    let mut builder = db2_proto::ddm::DdmBuilder::new(codepoints::SQLDTA);

    let mut data = Vec::new();
    for param in params {
        let value = param.to_db2_value();
        let encoded = types::encode_db2_value(&value);
        data.extend_from_slice(&encoded);
    }
    builder.add_raw(&data);

    builder.build()
}

/// Parse column info from an SQLDARD DDM object.
fn parse_sqldard_columns(obj: &DdmObject) -> Vec<ColumnInfo> {
    let dard = match db2_proto::replies::sqldard::parse_sqldard(obj) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    dard.columns
        .into_iter()
        .map(|col| ColumnInfo {
            name: col.name.clone(),
            type_name: format!("{:?}", col.db2_type),
            nullable: col.nullable,
            precision: if col.precision > 0 {
                Some(col.precision as u16)
            } else {
                None
            },
            scale: if col.scale > 0 {
                Some(col.scale as u16)
            } else {
                None
            },
        })
        .collect()
}

/// Simple heuristic to determine if a SQL string is a query (SELECT).
fn sql_is_query(sql: &str) -> bool {
    let trimmed = sql.trim().to_uppercase();
    trimmed.starts_with("SELECT")
        || trimmed.starts_with("WITH")
        || trimmed.starts_with("VALUES")
        || trimmed.starts_with("CALL")
}
