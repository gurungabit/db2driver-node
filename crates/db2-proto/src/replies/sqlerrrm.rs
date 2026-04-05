//! Parse SQL error reply messages (SQLERRRM and related).
use crate::codepoints::*;
use crate::ddm::DdmObject;
use crate::{ProtoError, Result};

/// SQL error reply message data.
#[derive(Debug, Clone)]
pub struct SqlErrorReply {
    /// Severity code.
    pub severity_code: u16,
    /// Error-related parameters (raw, for diagnostics).
    pub parameters: Vec<(u16, Vec<u8>)>,
}

impl SqlErrorReply {
    /// Check if this is a severe or permanent error.
    pub fn is_error(&self) -> bool {
        self.severity_code >= SRVCOD_ERROR
    }
}

/// Parse an SQLERRRM DDM object.
pub fn parse_sqlerrrm(obj: &DdmObject) -> Result<SqlErrorReply> {
    if obj.code_point != SQLERRRM {
        return Err(ProtoError::UnexpectedReply {
            expected: SQLERRRM,
            actual: obj.code_point,
        });
    }

    let params = obj.parameters();
    let mut severity_code: u16 = SRVCOD_ERROR;
    let mut raw_params = Vec::new();

    for param in &params {
        match param.code_point {
            SVRCOD => {
                severity_code = param.as_u16().unwrap_or(SRVCOD_ERROR);
            }
            _ => {
                raw_params.push((param.code_point, param.data.clone()));
            }
        }
    }

    Ok(SqlErrorReply {
        severity_code,
        parameters: raw_params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sqlerrrm() {
        let mut builder = crate::ddm::DdmBuilder::new(SQLERRRM);
        builder.add_u16(SVRCOD, SRVCOD_ERROR);
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let reply = parse_sqlerrrm(&obj).unwrap();
        assert!(reply.is_error());
    }
}
