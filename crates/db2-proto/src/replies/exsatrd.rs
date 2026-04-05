/// Parse EXSATRD (Exchange Server Attributes Reply Data).

use crate::codepoints::*;
use crate::ddm::DdmObject;
use crate::{ProtoError, Result};

/// Server attributes returned by EXSATRD.
#[derive(Debug, Clone)]
pub struct ServerAttributes {
    pub external_name: Option<String>,
    pub server_name: Option<String>,
    pub server_class_name: Option<String>,
    pub product_release_level: Option<String>,
    pub manager_levels: Vec<(u16, u16)>,
}

/// Parse an EXSATRD DDM object.
pub fn parse_exsatrd(obj: &DdmObject) -> Result<ServerAttributes> {
    if obj.code_point != EXSATRD {
        return Err(ProtoError::UnexpectedReply {
            expected: EXSATRD,
            actual: obj.code_point,
        });
    }

    let params = obj.parameters();
    let mut attrs = ServerAttributes {
        external_name: None,
        server_name: None,
        server_class_name: None,
        product_release_level: None,
        manager_levels: Vec::new(),
    };

    for param in &params {
        match param.code_point {
            EXTNAM => {
                attrs.external_name = Some(param.as_ebcdic());
            }
            SRVNAM => {
                attrs.server_name = Some(param.as_ebcdic());
            }
            SRVCLSNM => {
                attrs.server_class_name = Some(param.as_ebcdic());
            }
            SRVRLSLV => {
                attrs.product_release_level = Some(param.as_ebcdic());
            }
            MGRLVLLS => {
                // Pairs of (code_point: u16, level: u16)
                let data = &param.data;
                let mut offset = 0;
                while offset + 4 <= data.len() {
                    let cp = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    let lvl = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                    attrs.manager_levels.push((cp, lvl));
                    offset += 4;
                }
            }
            _ => {}
        }
    }

    Ok(attrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::excsat::build_excsat_default;
    use crate::ddm::DdmObject;

    #[test]
    fn test_parse_exsatrd_from_built_excsat() {
        // Build a hand-crafted EXSATRD with EBCDIC-encoded strings (as a real server would send).
        let mut builder = crate::ddm::DdmBuilder::new(EXSATRD);
        builder.add_ebcdic_string(EXTNAM, "DB2/LINUX");
        builder.add_ebcdic_string(SRVNAM, "testserver");
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let attrs = parse_exsatrd(&obj).unwrap();
        assert_eq!(attrs.external_name.as_deref(), Some("DB2/LINUX"));
        assert_eq!(attrs.server_name.as_deref(), Some("testserver"));
        let _ = build_excsat_default(); // ensure it compiles
    }
}
