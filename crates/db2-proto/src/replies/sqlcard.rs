//! Parse SQLCARD (SQL Communications Area Reply Data).
use crate::codepage::ebcdic037_to_utf8;
///
/// SQLCARD contains:
///   - Null indicator (1 byte): 0xFF = null (success, no details), 0x00 = has data
///   - If not null:
///     - SQLCODE (4 bytes, BE i32): negative=error, positive=warning, 0=success
///     - SQLSTATE (5 bytes, EBCDIC)
///     - SQLERRPROC (8 bytes, EBCDIC)
///     - SQLCAXGRP: error detail group
///       - SQLERRD (6 x i32 = 24 bytes) — sqlerrd[2] (3rd element) = row count for DML
///       - SQLWARN (11 bytes of warning flags)
///       - SQLERRMC (length-prefixed EBCDIC string with tokens separated by 0xFF)
use crate::codepoints::SQLCARD;
use crate::ddm::DdmObject;
use crate::{ProtoError, Result};

/// Parsed SQL Communications Area.
#[derive(Debug, Clone)]
pub struct SqlCard {
    /// True if this is a null SQLCARD (meaning simple success with no details).
    pub is_null: bool,
    /// SQL return code: negative = error, 0 = success, positive = warning.
    pub sqlcode: i32,
    /// SQLSTATE (5-character string, e.g., "00000", "42S02").
    pub sqlstate: String,
    /// Procedure that generated the error.
    pub sqlerrproc: String,
    /// SQLERRD array (6 values).
    /// sqlerrd[2] typically contains the row count for INSERT/UPDATE/DELETE.
    pub sqlerrd: [i32; 6],
    /// SQL warning flags (11 bytes).
    pub sqlwarn: [u8; 11],
    /// Error message tokens (separated by 0xFF in the original encoding).
    pub sqlerrmc: String,
}

impl SqlCard {
    /// Create a null (success) SQLCARD.
    pub fn success() -> Self {
        Self {
            is_null: true,
            sqlcode: 0,
            sqlstate: "00000".to_string(),
            sqlerrproc: String::new(),
            sqlerrd: [0; 6],
            sqlwarn: [0; 11],
            sqlerrmc: String::new(),
        }
    }

    /// Is this a success result (SQLCODE >= 0)?
    pub fn is_success(&self) -> bool {
        self.sqlcode >= 0
    }

    /// Is this an error result (SQLCODE < 0)?
    pub fn is_error(&self) -> bool {
        self.sqlcode < 0
    }

    /// Is this a warning (SQLCODE > 0)?
    pub fn is_warning(&self) -> bool {
        self.sqlcode > 0
    }

    /// Get the row count from sqlerrd[2] (the third element).
    pub fn row_count(&self) -> i32 {
        self.sqlerrd[2]
    }
}

/// Parse an SQLCARD DDM object.
pub fn parse_sqlcard(obj: &DdmObject) -> Result<SqlCard> {
    if obj.code_point != SQLCARD {
        return Err(ProtoError::UnexpectedReply {
            expected: SQLCARD,
            actual: obj.code_point,
        });
    }

    parse_sqlcard_data(&obj.data)
}

/// Parse SQLCARD from raw data bytes (without the DDM header).
pub fn parse_sqlcard_data(data: &[u8]) -> Result<SqlCard> {
    if data.is_empty() {
        return Ok(SqlCard::success());
    }

    // First byte: null indicator
    let null_indicator = data[0];
    if null_indicator == 0xFF {
        return Ok(SqlCard::success());
    }

    // Minimum: 1 (null ind) + 4 (sqlcode) + 5 (sqlstate) + 8 (sqlerrproc) = 18
    if data.len() < 18 {
        return Err(ProtoError::InvalidSqlcard(format!(
            "SQLCARD data too short: {} bytes",
            data.len()
        )));
    }

    let mut offset = 1;

    // SQLCODE: 4 bytes BE i32
    let sqlcode = i32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    // SQLSTATE: 5 bytes EBCDIC
    let sqlstate = ebcdic037_to_utf8(&data[offset..offset + 5]);
    offset += 5;

    // SQLERRPROC: 8 bytes EBCDIC
    let sqlerrproc = ebcdic037_to_utf8(&data[offset..offset + 8]);
    offset += 8;

    // SQLCAXGRP - may or may not be present
    let mut sqlerrd = [0i32; 6];
    let mut sqlwarn = [0u8; 11];
    let mut sqlerrmc = String::new();

    // Check for SQLCAXGRP null indicator
    if offset < data.len() {
        let caxgrp_null = data[offset];
        offset += 1;

        if caxgrp_null != 0xFF && offset + 24 <= data.len() {
            // SQLERRD: 6 x i32 = 24 bytes
            for item in &mut sqlerrd {
                if offset + 4 <= data.len() {
                    *item = i32::from_be_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]);
                    offset += 4;
                }
            }

            // SQLWARN: 11 bytes
            if offset + 11 <= data.len() {
                sqlwarn.copy_from_slice(&data[offset..offset + 11]);
                offset += 11;
            }

            // SQLERRMC: variable length, 2-byte length prefix + EBCDIC data
            if offset + 2 <= data.len() {
                let errmc_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                if offset + errmc_len <= data.len() {
                    let errmc_bytes = &data[offset..offset + errmc_len];
                    // Convert from EBCDIC, replacing 0xFF separators with '; '
                    let mut tokens = Vec::new();
                    let mut current_token = Vec::new();
                    for &b in errmc_bytes {
                        if b == 0xFF {
                            if !current_token.is_empty() {
                                tokens.push(ebcdic037_to_utf8(&current_token));
                                current_token.clear();
                            }
                        } else {
                            current_token.push(b);
                        }
                    }
                    if !current_token.is_empty() {
                        tokens.push(ebcdic037_to_utf8(&current_token));
                    }
                    sqlerrmc = tokens.join("; ");
                }
            }
        }
    }

    Ok(SqlCard {
        is_null: false,
        sqlcode,
        sqlstate,
        sqlerrproc,
        sqlerrd,
        sqlwarn,
        sqlerrmc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_sqlcard() {
        let data = vec![0xFF];
        let card = parse_sqlcard_data(&data).unwrap();
        assert!(card.is_null);
        assert!(card.is_success());
        assert_eq!(card.sqlcode, 0);
    }

    #[test]
    fn test_sqlcard_with_data() {
        let mut data = Vec::new();
        data.push(0x00); // not null
        data.extend_from_slice(&100i32.to_be_bytes()); // sqlcode = 100 (no data found)
        data.extend_from_slice(&[0xF0, 0xF0, 0xF1, 0xF0, 0xF0]); // sqlstate "00100" in EBCDIC
        data.extend_from_slice(&[0x40; 8]); // sqlerrproc (spaces)

        let card = parse_sqlcard_data(&data).unwrap();
        assert!(!card.is_null);
        assert_eq!(card.sqlcode, 100);
        assert!(card.is_warning());
    }
}
