//! Parse QRYDTA (Query Answer Set Data).
//!
//! QRYDTA wraps the raw row data returned by the server.
//! The actual row format depends on the column descriptors from QRYDSC or SQLDARD.
use crate::codepoints::QRYDTA;
use crate::ddm::DdmObject;
use crate::{ProtoError, Result};

/// Parsed QRYDTA containing raw row data bytes.
#[derive(Debug, Clone)]
pub struct QueryData {
    /// Raw row data bytes for FD:OCA decoding.
    pub data: Vec<u8>,
}

/// Parse a QRYDTA DDM object.
///
/// The data is returned as-is for subsequent FD:OCA row decoding.
pub fn parse_qrydta(obj: &DdmObject) -> Result<QueryData> {
    if obj.code_point != QRYDTA {
        return Err(ProtoError::UnexpectedReply {
            expected: QRYDTA,
            actual: obj.code_point,
        });
    }

    Ok(QueryData {
        data: obj.data.clone(),
    })
}

/// Extract row data from QRYDTA, skipping the initial consistency bytes if present.
///
/// In the limited-block query protocol (LMTBLKPRC), QRYDTA may have no prefix.
/// In the fixed-row protocol, there may be an extra byte at the start.
/// This function returns the raw data; the caller should use fdoca::decode_rows.
pub fn extract_row_data(qrydta: &QueryData) -> &[u8] {
    &qrydta.data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_qrydta() {
        let mut builder = crate::ddm::DdmBuilder::new(QRYDTA);
        let row_bytes = vec![0x00, 0x00, 0x00, 0x2A]; // integer 42
        builder.add_raw(&row_bytes);
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let qd = parse_qrydta(&obj).unwrap();
        assert_eq!(qd.data, row_bytes);
    }
}
