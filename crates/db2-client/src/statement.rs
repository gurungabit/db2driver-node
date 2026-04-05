use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

use crate::column::ColumnInfo;
use crate::connection::ClientInner;
use crate::error::Error;
use crate::types::{self, QueryResult, ToSql};
use db2_proto::codepoints;
use db2_proto::dss::DssWriter;

/// A prepared SQL statement that can be executed multiple times with different parameters.
pub struct PreparedStatement {
    inner: Arc<Mutex<ClientInner>>,
    sql: String,
    section_number: u16,
    column_metadata: Vec<ColumnInfo>,
    prepared: bool,
}

impl PreparedStatement {
    /// Create a new PreparedStatement. Called internally by Client::prepare().
    pub(crate) fn new(
        inner: Arc<Mutex<ClientInner>>,
        sql: String,
        section_number: u16,
        column_metadata: Vec<ColumnInfo>,
    ) -> Self {
        PreparedStatement {
            inner,
            sql,
            section_number,
            column_metadata,
            prepared: true,
        }
    }

    /// Execute the prepared statement with the given parameters.
    pub async fn execute(&self, params: &[&dyn ToSql]) -> Result<QueryResult, Error> {
        if !self.prepared {
            return Err(Error::Other("Statement has been closed".into()));
        }

        let mut guard = self.inner.lock().await;
        if !guard.connected {
            return Err(Error::Connection("Not connected".into()));
        }

        debug!(
            "Executing prepared statement (section={}): {}",
            self.section_number, self.sql
        );

        let is_query = sql_is_query(&self.sql);
        let pkgnamcsn = db2_proto::commands::build_default_pkgnamcsn(
            &guard.config.database,
            self.section_number,
        );

        if is_query {
            // Use OPNQRY for query statements
            let corr_id = guard.next_correlation_id();
            let opnqry_data = db2_proto::commands::opnqry::build_opnqry(
                &pkgnamcsn,
                db2_proto::commands::opnqry::DEFAULT_QRYBLKSZ,
                Some(-1),
                codepoints::QRYPRCTYP_LMTBLKPRC,
                Some(guard.config.fetch_size),
                None,
            );
            let sqldta_data = build_sqldta(params);

            let mut writer = DssWriter::new(corr_id);
            writer.write_request(&opnqry_data, true);
            writer.write_object(&sqldta_data, false);
            let send_buf = writer.finish();
            guard.send_bytes(&send_buf).await?;

            let frames = guard.read_reply_frames().await?;
            guard
                .process_query_reply_public(&frames, &self.column_metadata)
                .await
        } else {
            // Use EXCSQLSTT for DML statements
            let corr_id = guard.next_correlation_id();
            let excsqlstt_data =
                db2_proto::commands::excsqlstt::build_excsqlstt_default(&pkgnamcsn);
            let sqldta_data = build_sqldta(params);

            let mut writer = DssWriter::new(corr_id);
            writer.write_request(&excsqlstt_data, true);
            writer.write_object(&sqldta_data, false);
            let send_buf = writer.finish();
            guard.send_bytes(&send_buf).await?;

            let frames = guard.read_reply_frames().await?;
            guard.process_execute_reply_public(&frames).await
        }
    }

    /// Close the prepared statement, releasing server-side resources.
    pub async fn close(mut self) -> Result<(), Error> {
        self.prepared = false;
        debug!(
            "Closed prepared statement (section={})",
            self.section_number
        );
        // In a full implementation, we would send a DRPPKG command to the server.
        // For now, just mark as closed.
        Ok(())
    }

    /// Get the SQL text of this prepared statement.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Get the column metadata from the prepare response.
    pub fn columns(&self) -> &[ColumnInfo] {
        &self.column_metadata
    }

    /// Get the section number assigned to this statement.
    pub fn section_number(&self) -> u16 {
        self.section_number
    }
}

/// Build SQLDTA DDM object for parameters.
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

/// Simple heuristic to determine if a SQL string is a query (SELECT).
fn sql_is_query(sql: &str) -> bool {
    let trimmed = sql.trim().to_uppercase();
    trimmed.starts_with("SELECT")
        || trimmed.starts_with("WITH")
        || trimmed.starts_with("VALUES")
        || trimmed.starts_with("CALL")
}
