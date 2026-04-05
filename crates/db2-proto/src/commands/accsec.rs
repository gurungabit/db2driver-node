//! Build ACCSEC (Access Security) command.
use crate::codepage::pad_rdbnam;
use crate::codepoints::*;
use crate::ddm::DdmBuilder;

/// Build an ACCSEC DDM command.
///
/// Parameters:
///   - security_mechanism: Security mechanism code (e.g., SECMEC_USRIDPWD)
///   - rdbnam: Database name (will be EBCDIC-encoded and padded to 18 bytes)
pub fn build_accsec(security_mechanism: u16, rdbnam: &str) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(ACCSEC);
    ddm.add_u16(SECMEC, security_mechanism);
    ddm.add_code_point(RDBNAM, &pad_rdbnam(rdbnam));
    ddm.build()
}

/// Build ACCSEC with user ID + password security mechanism.
pub fn build_accsec_usridpwd(rdbnam: &str) -> Vec<u8> {
    build_accsec(SECMEC_USRIDPWD, rdbnam)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_accsec() {
        let bytes = build_accsec_usridpwd("TESTDB");
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, ACCSEC);
        let params = obj.parameters();
        let secmec_param = params.iter().find(|p| p.code_point == SECMEC).unwrap();
        assert_eq!(secmec_param.as_u16().unwrap(), SECMEC_USRIDPWD);
        let rdbnam_param = params.iter().find(|p| p.code_point == RDBNAM).unwrap();
        assert_eq!(rdbnam_param.data.len(), 18);
    }
}
