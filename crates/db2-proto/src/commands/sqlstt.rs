/// Build SQLSTT (SQL Statement) DDM object.
///
/// SQLSTT carries the SQL text. It is typically sent as a chained Object DSS
/// following a PRPSQLSTT, EXCSQLIMM, or EXCSQLSTT command.

use crate::codepoints::SQLSTT;
use crate::ddm::DdmBuilder;

/// Build an SQLSTT DDM object carrying the SQL text.
///
/// The SQL text is encoded as UTF-8 (when using CCSID 1208, which is the default).
pub fn build_sqlstt(sql: &str) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(SQLSTT);
    // SQLSTT contains the raw SQL string as its data, without a sub-code-point.
    ddm.add_raw(sql.as_bytes());
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
        assert_eq!(String::from_utf8(obj.data).unwrap(), sql);
    }
}
