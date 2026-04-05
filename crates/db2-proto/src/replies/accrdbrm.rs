//! Parse ACCRDBRM (Access RDB Reply Message).
use crate::codepoints::*;
use crate::ddm::DdmObject;
use crate::{ProtoError, Result};

/// Access RDB reply data.
#[derive(Debug, Clone)]
pub struct AccRdbReply {
    /// Severity code.
    pub severity_code: u16,
    /// Server product identifier.
    pub product_id: Option<String>,
    /// Type definition name agreed upon.
    pub typdefnam: Option<String>,
    /// CCSID values from TYPDEFOVR.
    pub ccsid_sbc: Option<u16>,
    pub ccsid_dbc: Option<u16>,
    pub ccsid_mbc: Option<u16>,
}

impl AccRdbReply {
    /// Returns true if the RDB was accessed successfully.
    pub fn is_success(&self) -> bool {
        self.severity_code == SRVCOD_INFO || self.severity_code == SRVCOD_WARNING
    }
}

/// Parse an ACCRDBRM DDM object.
pub fn parse_accrdbrm(obj: &DdmObject) -> Result<AccRdbReply> {
    if obj.code_point != ACCRDBRM {
        return Err(ProtoError::UnexpectedReply {
            expected: ACCRDBRM,
            actual: obj.code_point,
        });
    }

    let params = obj.parameters();
    let mut reply = AccRdbReply {
        severity_code: 0,
        product_id: None,
        typdefnam: None,
        ccsid_sbc: None,
        ccsid_dbc: None,
        ccsid_mbc: None,
    };

    for param in &params {
        match param.code_point {
            SVRCOD => {
                reply.severity_code = param.as_u16().unwrap_or(0);
            }
            PRDID => {
                reply.product_id = Some(param.as_ebcdic());
            }
            TYPDEFNAM => {
                reply.typdefnam = Some(param.as_ebcdic());
            }
            TYPDEFOVR => {
                // Parse nested CCSID parameters
                parse_typdefovr(&param.data, &mut reply);
            }
            _ => {}
        }
    }

    Ok(reply)
}

/// Parse TYPDEFOVR nested parameters to extract CCSID values.
fn parse_typdefovr(data: &[u8], reply: &mut AccRdbReply) {
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        if len < 4 || offset + len > data.len() {
            break;
        }
        let cp = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        if len >= 6 {
            let val = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            match cp {
                CCSIDSBC => reply.ccsid_sbc = Some(val),
                CCSIDDBC => reply.ccsid_dbc = Some(val),
                CCSIDMBC => reply.ccsid_mbc = Some(val),
                _ => {}
            }
        }
        offset += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accrdbrm() {
        let mut builder = crate::ddm::DdmBuilder::new(ACCRDBRM);
        builder.add_u16(SVRCOD, SRVCOD_INFO);
        builder.add_ebcdic_string(PRDID, "DSN12015");

        // Build TYPDEFOVR with CCSID values
        let mut typdefovr_data = Vec::new();
        typdefovr_data.extend_from_slice(&6u16.to_be_bytes());
        typdefovr_data.extend_from_slice(&CCSIDSBC.to_be_bytes());
        typdefovr_data.extend_from_slice(&1208u16.to_be_bytes());
        builder.add_code_point(TYPDEFOVR, &typdefovr_data);

        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let reply = parse_accrdbrm(&obj).unwrap();
        assert!(reply.is_success());
        assert_eq!(reply.ccsid_sbc, Some(1208));
    }
}
