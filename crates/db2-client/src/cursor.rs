use tracing::trace;

use crate::column::ColumnInfo;
use crate::connection::ClientInner;
use crate::error::Error;
use crate::row::Row;
use db2_proto::codepoints;
use db2_proto::dss::DssWriter;

/// Internal cursor for iterating over query result sets.
///
/// The cursor sends CNTQRY requests to fetch additional rows and
/// detects ENDQRYRM to know when the result set is exhausted.
pub(crate) struct Cursor {
    column_info: Vec<ColumnInfo>,
    descriptors: Vec<db2_proto::fdoca::ColumnDescriptor>,
    fetch_size: u32,
    closed: bool,
}

impl Cursor {
    /// Create a new cursor for fetching results.
    pub fn new(
        column_info: Vec<ColumnInfo>,
        descriptors: Vec<db2_proto::fdoca::ColumnDescriptor>,
        fetch_size: u32,
    ) -> Self {
        Cursor {
            column_info,
            descriptors,
            fetch_size,
            closed: false,
        }
    }

    /// Fetch the next batch of rows from the server via the given ClientInner.
    /// Returns (rows, end_of_query).
    pub async fn fetch_next_from(
        &mut self,
        inner: &mut ClientInner,
    ) -> Result<(Vec<Row>, bool), Error> {
        if self.closed {
            return Ok((Vec::new(), true));
        }

        let corr_id = inner.next_correlation_id();
        let pkgnamcsn = db2_proto::commands::build_default_pkgnamcsn(
            &inner.config.database,
            1, // section number for continuation
        );

        let cntqry_data = db2_proto::commands::cntqry::build_cntqry(
            &pkgnamcsn,
            db2_proto::commands::opnqry::DEFAULT_QRYBLKSZ,
            Some(-1),
            Some(self.fetch_size),
        );

        let mut writer = DssWriter::new(corr_id);
        writer.write_request(&cntqry_data, false);
        let send_buf = writer.finish();
        inner.send_bytes(&send_buf).await?;

        let frames = inner.read_reply_frames().await?;
        let mut rows = Vec::new();
        let mut end_of_query = false;

        for frame in &frames {
            let obj = ClientInner::parse_ddm(&frame.payload)?;

            match obj.code_point {
                codepoints::QRYDTA => {
                    trace!("Cursor: received QRYDTA");
                    let decoded_rows = db2_proto::fdoca::decode_rows(&obj.data, &self.descriptors)
                        .map_err(|e| Error::Protocol(e.to_string()))?;
                    for values in decoded_rows {
                        let col_names: Vec<String> =
                            self.column_info.iter().map(|c| c.name.clone()).collect();
                        rows.push(Row::new(col_names, values));
                    }
                }
                codepoints::ENDQRYRM => {
                    trace!("Cursor: end of query");
                    end_of_query = true;
                    self.closed = true;
                }
                codepoints::SQLCARD => {
                    trace!("Cursor: received SQLCARD");
                    let card = db2_proto::replies::sqlcard::parse_sqlcard(&obj)
                        .map_err(|e| Error::Protocol(e.to_string()))?;
                    if card.is_error() {
                        return Err(Error::Sql {
                            sqlstate: card.sqlstate,
                            sqlcode: card.sqlcode,
                            message: format!("Error during fetch: {}", card.sqlerrmc),
                        });
                    }
                }
                _ => {
                    trace!("Cursor: ignoring reply codepoint 0x{:04X}", obj.code_point);
                }
            }
        }

        Ok((rows, end_of_query))
    }
}
