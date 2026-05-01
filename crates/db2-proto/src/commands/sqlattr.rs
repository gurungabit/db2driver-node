//! Build SQLATTR (SQL Statement Attributes) DDM object.
use crate::codepoints::SQLATTR;
use crate::ddm::DdmBuilder;

/// Build SQLATTR for a read-only cursor.
///
/// Db2 for z/OS expects SELECT statements opened through OPNQRY to be prepared
/// as cursors. IBM requester traces include this attribute before SQLSTT.
pub fn build_sqlattr_for_read_only_cursor() -> Vec<u8> {
    let attribute = b"FOR READ ONLY ";
    let mut ddm = DdmBuilder::new(SQLATTR);
    ddm.add_raw(&(attribute.len() as u16).to_be_bytes());
    ddm.add_raw(attribute);
    ddm.add_raw(&[0x00, 0x00]);
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
        assert_eq!(u16::from_be_bytes([obj.data[0], obj.data[1]]), 14);
        assert_eq!(&obj.data[2..16], b"FOR READ ONLY ");
        assert_eq!(&obj.data[16..], &[0x00, 0x00]);
    }
}
