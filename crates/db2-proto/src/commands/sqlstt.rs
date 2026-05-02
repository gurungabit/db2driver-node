//! Build SQLSTT (SQL Statement) DDM object.
//!
//! SQLSTT carries the SQL text. It is typically sent as a chained Object DSS
//! following a PRPSQLSTT, EXCSQLIMM, or EXCSQLSTT command.
use crate::codepoints::SQLSTT;
use crate::ddm::DdmBuilder;

/// Build an SQLSTT DDM object carrying the SQL text.
///
/// The SQLSTT data format used by DB2 LUW:
///   - 3 zero bytes (padding/flags)
///   - 2-byte big-endian SQL text length
///   - SQL text as UTF-8
///   - 0xFF terminator
pub fn build_sqlstt(sql: &str) -> Vec<u8> {
    let sql_bytes = sql.as_bytes();
    let mut ddm = DdmBuilder::new(SQLSTT);

    // 3 zero bytes (padding/flags)
    ddm.add_raw(&[0x00, 0x00, 0x00]);
    ddm.add_raw(&(sql_bytes.len() as u16).to_be_bytes());

    // SQL text
    ddm.add_raw(sql_bytes);

    // 0xFF terminator
    ddm.add_raw(&[0xFF]);

    ddm.build()
}

/// Build an SQLAM 7+ nullable single-byte character payload.
///
/// SQLSTT and SQLATTR use the same encoded-string group. For our current
/// z/OS path we send the mixed-byte value as null and the single-byte value
/// as the SQL text:
///   - 0xFF: nullable mixed string is null
///   - 0x00: nullable single-byte string is present
///   - 4-byte big-endian length
///   - text in the negotiated source CCSID
pub(crate) fn build_zos_nocs_payload(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut payload = Vec::with_capacity(6 + bytes.len());
    payload.push(0xFF);
    payload.push(0x00);
    payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(bytes);
    payload
}

/// Build an SQLSTT object using the z/OS/JCC SQL statement group shape.
pub fn build_sqlstt_zos(sql: &str) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(SQLSTT);
    ddm.add_raw(&build_zos_nocs_payload(sql));
    ddm.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_sqlstt() {
        let sql = "SELECT * FROM employees WHERE id = 1";
        let bytes = build_sqlstt(sql);
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, SQLSTT);
        // Data format: 3 zero bytes + 2-byte length + SQL text + 0xFF terminator
        assert_eq!(obj.data[0..3], [0x00, 0x00, 0x00]);
        assert_eq!(
            u16::from_be_bytes([obj.data[3], obj.data[4]]) as usize,
            sql.len()
        );
        let sql_start = 5;
        let sql_end = sql_start + sql.len();
        assert_eq!(&obj.data[sql_start..sql_end], sql.as_bytes());
        assert_eq!(obj.data[sql_end], 0xFF);
    }

    #[test]
    fn test_build_sqlstt_zos() {
        let sql = "Select * from PHDAMVAR.ward";
        let bytes = build_sqlstt_zos(sql);
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, SQLSTT);
        assert_eq!(
            u32::from_be_bytes([obj.data[2], obj.data[3], obj.data[4], obj.data[5]]) as usize,
            sql.len()
        );
        assert_eq!(&obj.data[..2], &[0xFF, 0x00]);
        assert_eq!(&obj.data[6..6 + sql.len()], sql.as_bytes());
    }
}
