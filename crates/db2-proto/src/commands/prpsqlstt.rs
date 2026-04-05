/// Build PRPSQLSTT (Prepare SQL Statement) command.

use crate::codepoints::*;
use crate::ddm::DdmBuilder;

/// Build a PRPSQLSTT DDM command.
///
/// Parameters:
///   - pkgnamcsn: Pre-built PKGNAMCSN bytes (see commands::build_pkgnamcsn)
///   - rtnsqlda: Whether to return SQLDA (descriptor area) with the prepare response
///     - 0 = do not return
///     - 1 = return standard
///     - 2 = return extended
pub fn build_prpsqlstt(pkgnamcsn: &[u8], rtnsqlda: Option<u16>) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(PRPSQLSTT);
    ddm.add_code_point(PKGNAMCSN, pkgnamcsn);
    if let Some(val) = rtnsqlda {
        ddm.add_u16(RTNSQLDA, val);
    }
    ddm.build()
}

/// Build PRPSQLSTT requesting the SQL descriptor area.
pub fn build_prpsqlstt_with_sqlda(pkgnamcsn: &[u8]) -> Vec<u8> {
    build_prpsqlstt(pkgnamcsn, Some(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::build_default_pkgnamcsn;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_prpsqlstt() {
        let pkgnamcsn = build_default_pkgnamcsn("TESTDB", 1);
        let bytes = build_prpsqlstt_with_sqlda(&pkgnamcsn);
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, PRPSQLSTT);
    }
}
