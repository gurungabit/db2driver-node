/// Build CLSQRY (Close Query) command.

use crate::codepoints::*;
use crate::ddm::DdmBuilder;

/// Build a CLSQRY DDM command.
///
/// Parameters:
///   - pkgnamcsn: Pre-built PKGNAMCSN bytes identifying the query to close
pub fn build_clsqry(pkgnamcsn: &[u8]) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(CLSQRY);
    ddm.add_code_point(PKGNAMCSN, pkgnamcsn);
    ddm.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::build_default_pkgnamcsn;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_clsqry() {
        let pkgnamcsn = build_default_pkgnamcsn("TESTDB", 1);
        let bytes = build_clsqry(&pkgnamcsn);
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, CLSQRY);
    }
}
