//! Build SECCHK (Security Check) command.
use crate::codepage::{pad_rdbnam, utf8_to_ebcdic037};
use crate::codepoints::*;
use crate::ddm::DdmBuilder;
use crate::{ProtoError, Result};

/// Build a SECCHK DDM command with user ID, password, and database name.
///
/// Parameters:
///   - security_mechanism: Security mechanism code
///   - rdbnam: Database name (included for DB2 LUW compatibility)
///   - user_id: User ID (will be EBCDIC-encoded)
///   - password: Password (will be EBCDIC-encoded)
pub fn build_secchk(
    security_mechanism: u16,
    rdbnam: &str,
    user_id: &str,
    password: &str,
) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(SECCHK);
    ddm.add_u16(SECMEC, security_mechanism);
    ddm.add_code_point(RDBNAM, &pad_rdbnam(rdbnam));
    ddm.add_code_point(USRID, &utf8_to_ebcdic037(user_id));
    ddm.add_code_point(PASSWORD, &utf8_to_ebcdic037(password));
    ddm.build()
}

/// Build SECCHK for user ID + password authentication.
pub fn build_secchk_usridpwd(rdbnam: &str, user_id: &str, password: &str) -> Vec<u8> {
    build_secchk(SECMEC_USRIDPWD, rdbnam, user_id, password)
}

/// Build SECCHK for encrypted user ID + password authentication (SECMEC 0x0009).
///
/// The user ID and password are encrypted with the Diffie-Hellman session key
/// negotiated through ACCSEC/ACCSECRD, then sent as two SECTKN parameters.
pub fn build_secchk_eusridpwd(
    rdbnam: &str,
    user_id: &str,
    password: &str,
    server_sectkn: &[u8],
    client_private: &[u8],
) -> Result<Vec<u8>> {
    if server_sectkn.len() != 32 {
        return Err(ProtoError::Other(format!(
            "ACCSECRD returned an invalid SECTKN for encrypted authentication: expected 32 bytes, got {}",
            server_sectkn.len()
        )));
    }

    let session_key = crate::secmec9::calculate_session_key(server_sectkn, client_private);
    let encrypted_user_id = crate::secmec9::encrypt_userid(&session_key, server_sectkn, user_id);
    let encrypted_password =
        crate::secmec9::encrypt_password(&session_key, server_sectkn, password);

    let mut ddm = DdmBuilder::new(SECCHK);
    ddm.add_u16(SECMEC, SECMEC_EUSRIDPWD);
    ddm.add_code_point(RDBNAM, &pad_rdbnam(rdbnam));
    ddm.add_code_point(SECTKN, &encrypted_user_id);
    ddm.add_code_point(SECTKN, &encrypted_password);
    Ok(ddm.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_secchk() {
        let bytes = build_secchk_usridpwd("testdb", "db2inst1", "password123");
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, SECCHK);
        let params = obj.parameters();
        assert!(params.iter().any(|p| p.code_point == RDBNAM));
        assert!(params.iter().any(|p| p.code_point == USRID));
        assert!(params.iter().any(|p| p.code_point == PASSWORD));
    }

    #[test]
    fn test_build_secchk_eusridpwd() {
        let client_private = crate::secmec9::generate_private_key();
        let server_private = crate::secmec9::generate_private_key();
        let server_public = crate::secmec9::calculate_public_key(&server_private);

        let bytes = build_secchk_eusridpwd(
            "testdb",
            "db2inst1",
            "password123",
            &server_public,
            &client_private,
        )
        .unwrap();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, SECCHK);
        let params = obj.parameters();
        assert!(params.iter().any(|p| p.code_point == RDBNAM));
        assert_eq!(params.iter().filter(|p| p.code_point == SECTKN).count(), 2);
        assert!(!params.iter().any(|p| p.code_point == USRID));
        assert!(!params.iter().any(|p| p.code_point == PASSWORD));
    }
}
