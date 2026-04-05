//! Build RDBCMM (RDB Commit Unit of Work) command.
use crate::codepoints::RDBCMM;
use crate::ddm::DdmBuilder;

/// Build an RDBCMM DDM command.
///
/// This is a simple command with no required parameters.
/// It commits the current unit of work (transaction).
pub fn build_rdbcmm() -> Vec<u8> {
    let ddm = DdmBuilder::new(RDBCMM);
    ddm.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_rdbcmm() {
        let bytes = build_rdbcmm();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, RDBCMM);
        assert!(obj.data.is_empty());
    }
}
