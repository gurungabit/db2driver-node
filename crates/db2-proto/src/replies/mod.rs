pub mod exsatrd;
pub mod accsecrd;
pub mod secchkrm;
pub mod accrdbrm;
pub mod sqlerrrm;
pub mod sqlcard;
pub mod sqldard;
pub mod qrydta;
pub mod opnqryrm;
pub mod endqryrm;

use crate::Result;

/// Simplified column description returned by parse_sqldard.
#[derive(Debug, Clone)]
pub struct ColumnDesc {
    pub name: String,
    pub type_name: String,
    pub nullable: bool,
    pub precision: Option<u16>,
    pub scale: Option<u16>,
}

/// Parse SQLCARD data, returning (sqlcode, sqlstate, update_count).
///
/// This is a convenience wrapper around `sqlcard::parse_sqlcard_data`.
pub fn parse_sqlcard(data: &[u8]) -> Result<(i32, String, i64)> {
    let card = sqlcard::parse_sqlcard_data(data)?;
    let sqlcode = card.sqlcode;
    let update_count = card.row_count() as i64;
    Ok((sqlcode, card.sqlstate, update_count))
}

/// Parse SQLDARD data, returning a vector of column descriptions.
///
/// This is a convenience wrapper around `sqldard::parse_sqldard_data`.
pub fn parse_sqldard(data: &[u8]) -> Result<Vec<ColumnDesc>> {
    let dard = sqldard::parse_sqldard_data(data)?;
    let cols = dard
        .columns
        .into_iter()
        .map(|c| {
            let type_name = format!("{:?}", c.db2_type);
            let (precision, scale) = match &c.db2_type {
                crate::types::Db2Type::Decimal { precision, scale } => {
                    (Some(*precision as u16), Some(*scale as u16))
                }
                _ => (None, None),
            };
            ColumnDesc {
                name: c.name,
                type_name,
                nullable: c.nullable,
                precision,
                scale,
            }
        })
        .collect();
    Ok(cols)
}
