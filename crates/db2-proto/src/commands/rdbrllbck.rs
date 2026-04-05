/// Build RDBRLLBCK (RDB Rollback Unit of Work) command.

use crate::codepoints::RDBRLLBCK;
use crate::ddm::DdmBuilder;

/// Build an RDBRLLBCK DDM command.
///
/// This is a simple command with no required parameters.
/// It rolls back the current unit of work (transaction).
pub fn build_rdbrllbck() -> Vec<u8> {
    let ddm = DdmBuilder::new(RDBRLLBCK);
    ddm.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_rdbrllbck() {
        let bytes = build_rdbrllbck();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, RDBRLLBCK);
        assert!(obj.data.is_empty());
    }
}
