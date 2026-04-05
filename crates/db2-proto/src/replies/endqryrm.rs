//! Parse ENDQRYRM (End of Query Reply Message).
//!
//! This reply signals that the query result set is exhausted.
use crate::codepoints::*;
use crate::ddm::DdmObject;
use crate::{ProtoError, Result};

/// End of query reply data.
#[derive(Debug, Clone)]
pub struct EndQueryReply {
    /// Severity code.
    pub severity_code: u16,
    /// RDB rule set violation (if any).
    pub rdbnam: Option<String>,
}

impl EndQueryReply {
    /// Returns true if this is a normal end-of-data (not an error).
    pub fn is_normal_end(&self) -> bool {
        self.severity_code == SRVCOD_INFO || self.severity_code == SRVCOD_WARNING
    }
}

/// Parse an ENDQRYRM DDM object.
pub fn parse_endqryrm(obj: &DdmObject) -> Result<EndQueryReply> {
    if obj.code_point != ENDQRYRM {
        return Err(ProtoError::UnexpectedReply {
            expected: ENDQRYRM,
            actual: obj.code_point,
        });
    }

    let params = obj.parameters();
    let mut severity_code: u16 = 0;
    let mut rdbnam: Option<String> = None;

    for param in &params {
        match param.code_point {
            SVRCOD => {
                severity_code = param.as_u16().unwrap_or(0);
            }
            RDBNAM => {
                rdbnam = Some(param.as_ebcdic().trim().to_string());
            }
            _ => {}
        }
    }

    Ok(EndQueryReply {
        severity_code,
        rdbnam,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_endqryrm() {
        let mut builder = crate::ddm::DdmBuilder::new(ENDQRYRM);
        builder.add_u16(SVRCOD, SRVCOD_WARNING);
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let reply = parse_endqryrm(&obj).unwrap();
        assert!(reply.is_normal_end());
    }
}
