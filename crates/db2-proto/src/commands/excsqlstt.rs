/// Build EXCSQLSTT (Execute SQL Statement) command.

use crate::codepoints::*;
use crate::ddm::DdmBuilder;

/// Build an EXCSQLSTT DDM command.
///
/// Parameters:
///   - pkgnamcsn: Pre-built PKGNAMCSN bytes
///   - rtnsqlda: Whether to return SQLDA (0=no, 1=standard, 2=extended)
pub fn build_excsqlstt(pkgnamcsn: &[u8], rtnsqlda: Option<u16>) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(EXCSQLSTT);
    ddm.add_code_point(PKGNAMCSN, pkgnamcsn);
    if let Some(val) = rtnsqlda {
        ddm.add_u16(RTNSQLDA, val);
    }
    ddm.build()
}

/// Build EXCSQLSTT without requesting SQLDA return.
pub fn build_excsqlstt_default(pkgnamcsn: &[u8]) -> Vec<u8> {
    build_excsqlstt(pkgnamcsn, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::build_default_pkgnamcsn;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_excsqlstt() {
        let pkgnamcsn = build_default_pkgnamcsn("TESTDB", 1);
        let bytes = build_excsqlstt_default(&pkgnamcsn);
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, EXCSQLSTT);
    }
}
