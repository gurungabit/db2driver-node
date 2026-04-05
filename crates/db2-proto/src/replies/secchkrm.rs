//! Parse SECCHKRM (Security Check Reply Message).
use crate::codepoints::*;
use crate::ddm::DdmObject;
use crate::{ProtoError, Result};

/// Security check reply.
#[derive(Debug, Clone)]
pub struct SecChkReply {
    /// Severity code (0 = success, 8 = error, etc.)
    pub severity_code: u16,
    /// Security check code (0 = success, specific codes for different failures)
    pub security_check_code: Option<u8>,
}

impl SecChkReply {
    /// Returns true if authentication succeeded.
    pub fn is_success(&self) -> bool {
        self.severity_code == SRVCOD_INFO
    }
}

/// Parse a SECCHKRM DDM object.
pub fn parse_secchkrm(obj: &DdmObject) -> Result<SecChkReply> {
    if obj.code_point != SECCHKRM {
        return Err(ProtoError::UnexpectedReply {
            expected: SECCHKRM,
            actual: obj.code_point,
        });
    }

    let params = obj.parameters();
    let mut severity_code: u16 = 0;
    let mut security_check_code: Option<u8> = None;

    for param in &params {
        match param.code_point {
            SVRCOD => {
                severity_code = param.as_u16().unwrap_or(0);
            }
            SECCHKCD => {
                if !param.data.is_empty() {
                    security_check_code = Some(param.data[0]);
                }
            }
            _ => {}
        }
    }

    Ok(SecChkReply {
        severity_code,
        security_check_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_secchkrm_success() {
        let mut builder = crate::ddm::DdmBuilder::new(SECCHKRM);
        builder.add_u16(SVRCOD, SRVCOD_INFO);
        builder.add_code_point(SECCHKCD, &[0x00]);
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let reply = parse_secchkrm(&obj).unwrap();
        assert!(reply.is_success());
        assert_eq!(reply.security_check_code, Some(0x00));
    }

    #[test]
    fn test_parse_secchkrm_failure() {
        let mut builder = crate::ddm::DdmBuilder::new(SECCHKRM);
        builder.add_u16(SVRCOD, SRVCOD_ERROR);
        builder.add_code_point(SECCHKCD, &[0x0F]); // invalid password
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let reply = parse_secchkrm(&obj).unwrap();
        assert!(!reply.is_success());
    }
}
