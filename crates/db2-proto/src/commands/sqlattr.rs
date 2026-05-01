//! Build SQLATTR (SQL Statement Attributes) DDM object.
use crate::codepoints::SQLATTR;
use crate::ddm::DdmBuilder;

/// Build SQLATTR for a read-only cursor.
///
/// Db2 for z/OS expects SELECT statements opened through OPNQRY to be prepared
/// as cursors. IBM requester traces include this attribute before SQLSTT.
pub fn build_sqlattr_for_read_only_cursor() -> Vec<u8> {
    let mut ddm = DdmBuilder::new(SQLATTR);
    ddm.add_raw(&[0x00, 0x00, 0x00, 0x00]);
    ddm.add_raw(&[0x0E]);
    ddm.add_raw(b"FOR READ ONLY ");
    ddm.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_sqlattr_for_read_only_cursor() {
        let bytes = build_sqlattr_for_read_only_cursor();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, SQLATTR);
        assert_eq!(&obj.data[..5], &[0x00, 0x00, 0x00, 0x00, 0x0E]);
        assert!(obj.data.ends_with(b"FOR READ ONLY "));
    }
}
