/// Build SECCHK (Security Check) command.

use crate::codepoints::*;
use crate::codepage::utf8_to_ebcdic037;
use crate::ddm::DdmBuilder;

/// Build a SECCHK DDM command with user ID and password.
///
/// Parameters:
///   - security_mechanism: Security mechanism code
///   - user_id: User ID (will be EBCDIC-encoded)
///   - password: Password (will be EBCDIC-encoded)
pub fn build_secchk(security_mechanism: u16, user_id: &str, password: &str) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(SECCHK);
    ddm.add_u16(SECMEC, security_mechanism);
    ddm.add_code_point(USRID, &utf8_to_ebcdic037(user_id));
    ddm.add_code_point(PASSWORD, &utf8_to_ebcdic037(password));
    ddm.build()
}

/// Build SECCHK with user ID only (no password).
pub fn build_secchk_usrid_only(user_id: &str) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(SECCHK);
    ddm.add_u16(SECMEC, SECMEC_USRIDONL);
    ddm.add_code_point(USRID, &utf8_to_ebcdic037(user_id));
    ddm.build()
}

/// Build SECCHK for user ID + password authentication.
pub fn build_secchk_usridpwd(user_id: &str, password: &str) -> Vec<u8> {
    build_secchk(SECMEC_USRIDPWD, user_id, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_secchk() {
        let bytes = build_secchk_usridpwd("db2inst1", "password123");
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, SECCHK);
        let params = obj.parameters();
        assert!(params.iter().any(|p| p.code_point == USRID));
        assert!(params.iter().any(|p| p.code_point == PASSWORD));
    }
}
