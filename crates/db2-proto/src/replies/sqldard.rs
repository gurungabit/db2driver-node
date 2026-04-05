//! Parse SQLDARD (SQL Descriptor Area Reply Data).
use crate::codepage::ebcdic037_to_utf8;
///
/// Contains column metadata for a prepared statement or open query.
/// The format is:
///   - SQLCARD data (embedded, variable length)
///   - Number of columns: u16 BE
///   - For each column:
///     - Column descriptor data (type, length, precision, scale, name, etc.)
use crate::codepoints::SQLDARD;
use crate::ddm::DdmObject;
use crate::replies::sqlcard::{parse_sqlcard_data, SqlCard};
use crate::types::Db2Type;
use crate::{ProtoError, Result};

/// Metadata for a single column.
#[derive(Debug, Clone)]
pub struct ColumnMetadata {
    /// Column index (0-based).
    pub index: usize,
    /// Column name.
    pub name: String,
    /// DB2 SQL type.
    pub db2_type: Db2Type,
    /// DRDA type code.
    pub drda_type: u8,
    /// Data length.
    pub length: u16,
    /// Whether the column is nullable.
    pub nullable: bool,
    /// Decimal precision (for DECIMAL type).
    pub precision: u8,
    /// Decimal scale (for DECIMAL type).
    pub scale: u8,
    /// CCSID of the column data.
    pub ccsid: u16,
    /// Base table name (if available).
    pub base_table_name: String,
    /// Schema name (if available).
    pub schema_name: String,
    /// Label (if available).
    pub label: String,
}

/// Parsed SQLDARD result.
#[derive(Debug, Clone)]
pub struct SqlDard {
    /// Embedded SQLCARD.
    pub sqlcard: SqlCard,
    /// Number of columns.
    pub num_columns: u16,
    /// Column metadata.
    pub columns: Vec<ColumnMetadata>,
}

/// Parse an SQLDARD DDM object.
pub fn parse_sqldard(obj: &DdmObject) -> Result<SqlDard> {
    if obj.code_point != SQLDARD {
        return Err(ProtoError::UnexpectedReply {
            expected: SQLDARD,
            actual: obj.code_point,
        });
    }

    parse_sqldard_data(&obj.data)
}

/// Parse SQLDARD from raw data bytes.
pub fn parse_sqldard_data(data: &[u8]) -> Result<SqlDard> {
    if data.is_empty() {
        return Err(ProtoError::Other("empty SQLDARD data".into()));
    }

    let mut offset = 0;

    // Parse embedded SQLCARD
    // The SQLCARD starts with a null indicator byte.
    let sqlcard_null = data[offset];
    let sqlcard;
    if sqlcard_null == 0xFF {
        sqlcard = SqlCard::success();
        offset += 1;
    } else {
        // Parse SQLCARD data — we need to figure out how much it consumes.
        // SQLCARD: 1 (null) + 4 (sqlcode) + 5 (sqlstate) + 8 (sqlerrproc) + SQLCAXGRP
        let sqlcard_start = offset;
        offset += 1 + 4 + 5 + 8; // minimum: null + sqlcode + sqlstate + sqlerrproc

        // SQLCAXGRP null indicator
        if offset < data.len() {
            let caxgrp_null = data[offset];
            offset += 1;
            if caxgrp_null != 0xFF {
                offset += 24; // SQLERRD (6 * 4)
                offset += 11; // SQLWARN
                              // SQLERRMC length-prefixed
                if offset + 2 <= data.len() {
                    let errmc_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2 + errmc_len;
                }
                // SQLERRMCD_ (diagnostic sections) — skip with null indicators
                // There may be additional SQLDIAGGRP data here; we try to skip null indicators
                while offset < data.len() && data[offset] == 0xFF {
                    offset += 1;
                    // Check if we've reached column count data
                    // Heuristic: if next two bytes could be a reasonable column count, stop
                    if offset + 2 <= data.len() {
                        let maybe_ncols = u16::from_be_bytes([data[offset], data[offset + 1]]);
                        if maybe_ncols > 0 && maybe_ncols < 10000 {
                            break;
                        }
                    }
                }
            }
        }

        sqlcard =
            parse_sqlcard_data(&data[sqlcard_start..offset]).unwrap_or_else(|_| SqlCard::success());
    }

    // Number of columns
    if offset + 2 > data.len() {
        return Ok(SqlDard {
            sqlcard,
            num_columns: 0,
            columns: Vec::new(),
        });
    }
    let num_columns = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // Parse column descriptors
    let mut columns = Vec::with_capacity(num_columns as usize);
    for i in 0..num_columns as usize {
        if offset >= data.len() {
            break;
        }
        match parse_column_descriptor(&data[offset..], i) {
            Ok((col, consumed)) => {
                columns.push(col);
                offset += consumed;
            }
            Err(_) => break,
        }
    }

    Ok(SqlDard {
        sqlcard,
        num_columns,
        columns,
    })
}

/// Parse a single column descriptor from SQLDARD data.
/// Returns (ColumnMetadata, bytes consumed).
fn parse_column_descriptor(data: &[u8], index: usize) -> Result<(ColumnMetadata, usize)> {
    // The column descriptor format (SQLDA column entry):
    //   - SQLPRECISION (2 bytes): precision
    //   - SQLSCALE (2 bytes): scale
    //   - SQLLENGTH (8 bytes): length (as i64, but we use lower bytes)
    //   - SQLTYPE (2 bytes): DRDA type code
    //   - SQLCCSID (2 bytes): CCSID
    //   - SQLDOPTGRP null indicator (1 byte)
    //   - If SQLDOPTGRP not null:
    //     - SQLNAME_LENGTH (2 bytes) + SQLNAME (variable, EBCDIC)
    //     - SQLLABEL_LENGTH (2 bytes) + SQLLABEL (variable, EBCDIC)
    //     - SQLCOMMENTS null indicator (1 byte)
    //     - etc.

    let min_len = 2 + 2 + 8 + 2 + 2; // = 16 bytes minimum
    if data.len() < min_len {
        return Err(ProtoError::BufferTooShort {
            expected: min_len,
            actual: data.len(),
        });
    }

    let mut offset = 0;

    let precision_raw = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let scale_raw = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // SQLLENGTH: 8 bytes (i64), but we only need the lower 2 or 4 bytes
    let length_i64 = i64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    offset += 8;
    let length = length_i64 as u16;

    let sql_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    let ccsid = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    let drda_type = sql_type as u8;
    let nullable = (drda_type & 0x01) != 0;
    let precision = precision_raw as u8;
    let scale = scale_raw as u8;
    let (db2_type, _) = Db2Type::from_drda_type(drda_type, length, precision, scale);

    let mut name = String::new();
    let mut label = String::new();
    let mut base_table_name = String::new();
    let mut schema_name = String::new();

    // SQLDOPTGRP null indicator
    if offset < data.len() {
        let opt_null = data[offset];
        offset += 1;

        if opt_null != 0xFF && offset + 2 <= data.len() {
            // SQLNAME
            let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if offset + name_len <= data.len() {
                name = ebcdic037_to_utf8(&data[offset..offset + name_len])
                    .trim()
                    .to_string();
                offset += name_len;
            }

            // SQLLABEL
            if offset + 2 <= data.len() {
                let label_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                if offset + label_len <= data.len() {
                    label = ebcdic037_to_utf8(&data[offset..offset + label_len])
                        .trim()
                        .to_string();
                    offset += label_len;
                }
            }

            // SQLCOMMENTS null indicator
            if offset < data.len() {
                let comments_null = data[offset];
                offset += 1;
                if comments_null != 0xFF && offset + 2 <= data.len() {
                    let comments_len =
                        u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2;
                    offset += comments_len; // skip comments
                }
            }

            // SQLUDTGRP null indicator
            if offset < data.len() {
                let udt_null = data[offset];
                offset += 1;
                if udt_null != 0xFF {
                    // Skip UDT group data — variable length, we just skip known fields
                    // UDT schema (2 + len), UDT name (2 + len)
                    for _ in 0..2 {
                        if offset + 2 <= data.len() {
                            let flen =
                                u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                            offset += 2 + flen;
                        }
                    }
                }
            }

            // SQLDXGRP null indicator (extended info: base table name, schema, etc.)
            if offset < data.len() {
                let dx_null = data[offset];
                offset += 1;
                if dx_null != 0xFF {
                    // SQLBASECOLNM
                    if offset + 2 <= data.len() {
                        let bcol_len =
                            u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                        offset += 2;
                        offset += bcol_len;
                    }
                    // SQLSCHEMA
                    if offset + 2 <= data.len() {
                        let schema_len =
                            u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                        offset += 2;
                        if offset + schema_len <= data.len() {
                            schema_name = ebcdic037_to_utf8(&data[offset..offset + schema_len])
                                .trim()
                                .to_string();
                            offset += schema_len;
                        }
                    }
                    // SQLTABLENAME
                    if offset + 2 <= data.len() {
                        let tbl_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                        offset += 2;
                        if offset + tbl_len <= data.len() {
                            base_table_name = ebcdic037_to_utf8(&data[offset..offset + tbl_len])
                                .trim()
                                .to_string();
                            offset += tbl_len;
                        }
                    }
                }
            }
        }
    }

    Ok((
        ColumnMetadata {
            index,
            name,
            db2_type,
            drda_type,
            length,
            nullable,
            precision,
            scale,
            ccsid,
            base_table_name,
            schema_name,
            label,
        },
        offset,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_sqldard() {
        // Build a minimal SQLDARD: null SQLCARD + 0 columns
        let mut data = Vec::new();
        data.push(0xFF); // null SQLCARD
        data.extend_from_slice(&0u16.to_be_bytes()); // 0 columns

        let mut builder = crate::ddm::DdmBuilder::new(SQLDARD);
        builder.add_raw(&data);
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();

        let dard = parse_sqldard(&obj).unwrap();
        assert_eq!(dard.num_columns, 0);
        assert!(dard.columns.is_empty());
        assert!(dard.sqlcard.is_success());
    }
}
