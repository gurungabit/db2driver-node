//! Build SECCHK (Security Check) command.
use crate::codepage::{pad_rdbnam, utf8_to_ebcdic037};
use crate::codepoints::*;
use crate::ddm::DdmBuilder;
use crate::{ProtoError, Result};

/// Encoding for credential string bytes sent in SECCHK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialEncoding {
    /// EBCDIC code page 037.
    Ebcdic037,
    /// UTF-8.
    Utf8,
}

impl CredentialEncoding {
    fn encode(self, value: &str) -> Vec<u8> {
        match self {
            CredentialEncoding::Ebcdic037 => utf8_to_ebcdic037(value),
            CredentialEncoding::Utf8 => value.as_bytes().to_vec(),
        }
    }
}

/// Encodings used by SECMEC 7 encrypted password authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedPasswordCredentialEncodings {
    /// Encoding for the clear USRID parameter.
    pub user_id: CredentialEncoding,
    /// Encoding for the password plaintext before encryption.
    pub password: CredentialEncoding,
    /// Encoding for the user-ID-derived password IV/token.
    pub password_token: CredentialEncoding,
}

impl EncryptedPasswordCredentialEncodings {
    pub fn same(credential_encoding: CredentialEncoding) -> Self {
        Self {
            user_id: credential_encoding,
            password: credential_encoding,
            password_token: credential_encoding,
        }
    }
}

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

/// Build a SECCHK DDM command with user ID and password credentials.
///
/// The database name is sent in ACCSEC/ACCRDB. Some DB2 z/OS servers reject
/// RDBNAM when it is repeated inside SECCHK, so package code should prefer
/// this builder unless it explicitly needs the legacy framing above.
pub fn build_secchk_without_rdbnam(
    security_mechanism: u16,
    user_id: &str,
    password: &str,
) -> Vec<u8> {
    build_secchk_without_rdbnam_with_encoding(
        security_mechanism,
        user_id,
        password,
        CredentialEncoding::Ebcdic037,
    )
}

/// Build a SECCHK DDM command with encoded user ID and password credentials.
pub fn build_secchk_without_rdbnam_with_encoding(
    security_mechanism: u16,
    user_id: &str,
    password: &str,
    credential_encoding: CredentialEncoding,
) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(SECCHK);
    ddm.add_u16(SECMEC, security_mechanism);
    ddm.add_code_point(USRID, &credential_encoding.encode(user_id));
    ddm.add_code_point(PASSWORD, &credential_encoding.encode(password));
    ddm.build()
}

/// Build SECCHK for user ID + password authentication.
///
/// The `rdbnam` argument is retained for API compatibility; it is not encoded
/// in SECCHK because the database name is already sent in ACCSEC/ACCRDB.
pub fn build_secchk_usridpwd(_rdbnam: &str, user_id: &str, password: &str) -> Vec<u8> {
    build_secchk_without_rdbnam(SECMEC_USRIDPWD, user_id, password)
}

/// Build SECCHK for user ID + password authentication with encoded credentials.
pub fn build_secchk_usridpwd_with_encoding(
    _rdbnam: &str,
    user_id: &str,
    password: &str,
    credential_encoding: CredentialEncoding,
) -> Vec<u8> {
    build_secchk_without_rdbnam_with_encoding(
        SECMEC_USRIDPWD,
        user_id,
        password,
        credential_encoding,
    )
}

/// Build SECCHK for encrypted user ID + password authentication (SECMEC 0x0009).
///
/// The user ID and password are encrypted with the Diffie-Hellman session key
/// negotiated through ACCSEC/ACCSECRD, then sent as two SECTKN parameters.
/// The `rdbnam` argument is retained for API compatibility; it is not encoded
/// in SECCHK because the database name is already sent in ACCSEC/ACCRDB.
pub fn build_secchk_eusridpwd(
    _rdbnam: &str,
    user_id: &str,
    password: &str,
    server_sectkn: &[u8],
    client_private: &[u8],
) -> Result<Vec<u8>> {
    build_secchk_eusridpwd_with_encoding(
        _rdbnam,
        user_id,
        password,
        server_sectkn,
        client_private,
        CredentialEncoding::Ebcdic037,
    )
}

/// Build SECCHK for encrypted user ID + password authentication with encoded credentials.
pub fn build_secchk_eusridpwd_with_encoding(
    _rdbnam: &str,
    user_id: &str,
    password: &str,
    server_sectkn: &[u8],
    client_private: &[u8],
    credential_encoding: CredentialEncoding,
) -> Result<Vec<u8>> {
    if server_sectkn.len() != 32 {
        return Err(ProtoError::Other(format!(
            "ACCSECRD returned an invalid SECTKN for encrypted authentication: expected 32 bytes, got {}",
            server_sectkn.len()
        )));
    }

    let session_key = crate::secmec9::calculate_session_key(server_sectkn, client_private);
    let encoded_user_id = credential_encoding.encode(user_id);
    let encoded_password = credential_encoding.encode(password);
    let encrypted_user_id =
        crate::secmec9::encrypt_userid_bytes(&session_key, server_sectkn, &encoded_user_id);
    let encrypted_password =
        crate::secmec9::encrypt_password_bytes(&session_key, server_sectkn, &encoded_password);

    let mut ddm = DdmBuilder::new(SECCHK);
    ddm.add_u16(SECMEC, SECMEC_EUSRIDPWD);
    ddm.add_code_point(SECTKN, &encrypted_user_id);
    ddm.add_code_point(SECTKN, &encrypted_password);
    Ok(ddm.build())
}

/// Build SECCHK for user ID + encrypted password authentication (SECMEC 0x0007).
///
/// The user ID is sent as a clear USRID parameter. The password is encrypted
/// with the Diffie-Hellman session key negotiated through ACCSEC/ACCSECRD and
/// sent as a SECTKN parameter.
pub fn build_secchk_usencpwd(
    _rdbnam: &str,
    user_id: &str,
    password: &str,
    server_sectkn: &[u8],
    client_private: &[u8],
) -> Result<Vec<u8>> {
    build_secchk_usencpwd_with_encoding(
        _rdbnam,
        user_id,
        password,
        server_sectkn,
        client_private,
        CredentialEncoding::Ebcdic037,
    )
}

/// Build SECCHK for user ID + encrypted password authentication with encoded credentials.
pub fn build_secchk_usencpwd_with_encoding(
    _rdbnam: &str,
    user_id: &str,
    password: &str,
    server_sectkn: &[u8],
    client_private: &[u8],
    credential_encoding: CredentialEncoding,
) -> Result<Vec<u8>> {
    build_secchk_usencpwd_with_encodings(
        _rdbnam,
        user_id,
        password,
        server_sectkn,
        client_private,
        EncryptedPasswordCredentialEncodings::same(credential_encoding),
    )
}

/// Build SECCHK for user ID + encrypted password authentication with separate
/// encodings for the clear user ID, encrypted password plaintext, and password IV token.
pub fn build_secchk_usencpwd_with_encodings(
    _rdbnam: &str,
    user_id: &str,
    password: &str,
    server_sectkn: &[u8],
    client_private: &[u8],
    credential_encodings: EncryptedPasswordCredentialEncodings,
) -> Result<Vec<u8>> {
    if server_sectkn.len() != 32 {
        return Err(ProtoError::Other(format!(
            "ACCSECRD returned an invalid SECTKN for encrypted password authentication: expected 32 bytes, got {}",
            server_sectkn.len()
        )));
    }

    let session_key = crate::secmec9::calculate_session_key(server_sectkn, client_private);
    let encoded_user_id = credential_encodings.user_id.encode(user_id);
    let encoded_password = credential_encodings.password.encode(password);
    let password_token = credential_encodings.password_token.encode(user_id);
    let encrypted_password = crate::secmec9::encrypt_password_with_userid_iv_bytes(
        &session_key,
        &password_token,
        &encoded_password,
    );

    let mut ddm = DdmBuilder::new(SECCHK);
    ddm.add_u16(SECMEC, SECMEC_USRENCPWD);
    ddm.add_code_point(USRID, &encoded_user_id);
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
        assert!(!params.iter().any(|p| p.code_point == RDBNAM));
        assert!(params.iter().any(|p| p.code_point == USRID));
        assert!(params.iter().any(|p| p.code_point == PASSWORD));
    }

    #[test]
    fn test_build_legacy_secchk_with_rdbnam() {
        let bytes = build_secchk(SECMEC_USRIDPWD, "testdb", "db2inst1", "password123");
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
        assert!(!params.iter().any(|p| p.code_point == RDBNAM));
        assert_eq!(params.iter().filter(|p| p.code_point == SECTKN).count(), 2);
        assert!(!params.iter().any(|p| p.code_point == USRID));
        assert!(!params.iter().any(|p| p.code_point == PASSWORD));
    }

    #[test]
    fn test_build_secchk_usencpwd() {
        let client_private = crate::secmec9::generate_private_key();
        let server_private = crate::secmec9::generate_private_key();
        let server_public = crate::secmec9::calculate_public_key(&server_private);

        let bytes = build_secchk_usencpwd(
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
        assert!(!params.iter().any(|p| p.code_point == RDBNAM));
        assert!(params.iter().any(|p| p.code_point == USRID));
        assert_eq!(params.iter().filter(|p| p.code_point == SECTKN).count(), 1);
        assert!(!params.iter().any(|p| p.code_point == PASSWORD));
    }

    #[test]
    fn test_build_secchk_usencpwd_utf8_credentials() {
        let client_private = crate::secmec9::generate_private_key();
        let server_private = crate::secmec9::generate_private_key();
        let server_public = crate::secmec9::calculate_public_key(&server_private);

        let bytes = build_secchk_usencpwd_with_encoding(
            "testdb",
            "db2inst1",
            "password123",
            &server_public,
            &client_private,
            CredentialEncoding::Utf8,
        )
        .unwrap();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let user = obj.find_param(USRID).expect("USRID should be present");

        assert_eq!(user.data, b"db2inst1");
        assert_eq!(
            obj.parameters()
                .iter()
                .filter(|p| p.code_point == SECTKN)
                .count(),
            1
        );
    }

    #[test]
    fn test_build_secchk_usencpwd_can_mix_password_encodings() {
        let client_private = crate::secmec9::generate_private_key();
        let server_private = crate::secmec9::generate_private_key();
        let server_public = crate::secmec9::calculate_public_key(&server_private);

        let bytes = build_secchk_usencpwd_with_encodings(
            "testdb",
            "db2inst1",
            "password123",
            &server_public,
            &client_private,
            EncryptedPasswordCredentialEncodings {
                user_id: CredentialEncoding::Utf8,
                password: CredentialEncoding::Ebcdic037,
                password_token: CredentialEncoding::Ebcdic037,
            },
        )
        .unwrap();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let user = obj.find_param(USRID).expect("USRID should be present");

        assert_eq!(user.data, b"db2inst1");
        assert_eq!(
            obj.parameters()
                .iter()
                .filter(|p| p.code_point == SECTKN)
                .count(),
            1
        );
    }
}
