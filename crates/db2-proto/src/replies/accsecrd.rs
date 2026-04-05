/// Parse ACCSECRD (Access Security Reply Data).

use crate::codepoints::*;
use crate::ddm::DdmObject;
use crate::{ProtoError, Result};

/// Access security reply data.
#[derive(Debug, Clone)]
pub struct AccSecReply {
    pub security_mechanism: u16,
    pub security_token: Option<Vec<u8>>,
}

/// Parse an ACCSECRD DDM object.
pub fn parse_accsecrd(obj: &DdmObject) -> Result<AccSecReply> {
    if obj.code_point != ACCSECRD {
        return Err(ProtoError::UnexpectedReply {
            expected: ACCSECRD,
            actual: obj.code_point,
        });
    }

    let params = obj.parameters();
    let mut secmec: Option<u16> = None;
    let mut sectkn: Option<Vec<u8>> = None;

    for param in &params {
        match param.code_point {
            SECMEC => {
                secmec = param.as_u16();
            }
            SECTKN => {
                sectkn = Some(param.data.clone());
            }
            _ => {}
        }
    }

    Ok(AccSecReply {
        security_mechanism: secmec.unwrap_or(0),
        security_token: sectkn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accsecrd() {
        let mut builder = crate::ddm::DdmBuilder::new(ACCSECRD);
        builder.add_u16(SECMEC, SECMEC_USRIDPWD);
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let reply = parse_accsecrd(&obj).unwrap();
        assert_eq!(reply.security_mechanism, SECMEC_USRIDPWD);
        assert!(reply.security_token.is_none());
    }
}
