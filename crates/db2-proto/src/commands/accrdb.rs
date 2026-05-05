//! Build ACCRDB (Access RDB) command.
use crate::codepage::{pad_ebcdic, utf8_to_ebcdic037};
use crate::codepoints::*;
use crate::ddm::DdmBuilder;

/// Default product identifier, aligned with current IBM JCC wire traces.
pub const DEFAULT_PRDID: &str = "JCC04370";

/// Default DRDA type definition name.
///
/// Default type definition name, aligned with current IBM JCC wire traces.
pub const DEFAULT_TYPDEFNAM: &str = "QTDSQLASC";

/// Default CCSID values.
pub const DEFAULT_CCSID_SBC: u16 = 1208; // UTF-8 single-byte
pub const DEFAULT_CCSID_DBC: u16 = 1200; // UTF-16
pub const DEFAULT_CCSID_MBC: u16 = 1208; // UTF-8 mixed-byte

fn build_luw_crrtkn() -> Vec<u8> {
    let mut token = utf8_to_ebcdic037("NF000001");
    token.push(0x4B); // EBCDIC '.'
    token.extend_from_slice(&utf8_to_ebcdic037("C0A5"));
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts_bytes = ts.to_be_bytes();
    token.extend_from_slice(&ts_bytes[2..8]);
    token
}

fn pad_ascii(name: &str, length: usize) -> Vec<u8> {
    let mut bytes = name.as_bytes().to_vec();
    bytes.truncate(length);
    bytes.resize(length, b' ');
    bytes
}

/// Build an ACCRDB DDM command.
///
/// Parameters:
///   - rdbnam: Database name
///   - prdid: Product specific identifier (e.g., "JCC04200")
///   - typdefnam: Type definition name (e.g., "QTDSQLASC")
///   - ccsid_sbc: CCSID for single-byte characters
///   - ccsid_dbc: CCSID for double-byte characters
///   - ccsid_mbc: CCSID for mixed-byte characters
pub fn build_accrdb(
    rdbnam: &str,
    prdid: &str,
    typdefnam: &str,
    ccsid_sbc: u16,
    ccsid_dbc: u16,
    ccsid_mbc: u16,
) -> Vec<u8> {
    build_accrdb_with_optional_type_definition(
        rdbnam,
        prdid,
        Some(typdefnam),
        ccsid_sbc,
        ccsid_dbc,
        ccsid_mbc,
    )
}

/// Build an ACCRDB DDM command, optionally omitting TYPDEFNAM/TYPDEFOVR.
pub fn build_accrdb_with_optional_type_definition(
    rdbnam: &str,
    prdid: &str,
    typdefnam: Option<&str>,
    ccsid_sbc: u16,
    ccsid_dbc: u16,
    ccsid_mbc: u16,
) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(ACCRDB);
    ddm.add_code_point(RDBNAM, &pad_ascii(rdbnam, 18));
    ddm.add_code_point(RDBACCCL, &SQLAM.to_be_bytes());

    // JCC sends ACCRDB character fields in the source CCSID (UTF-8), not EBCDIC.
    ddm.add_string(PRDID, prdid);

    if let Some(typdefnam) = typdefnam {
        ddm.add_string(TYPDEFNAM, typdefnam);

        // TYPDEFOVR contains CCSID sub-parameters.
        let mut typdefovr_data = Vec::new();
        // CCSIDSBC
        let ccsid_sbc_bytes = ccsid_sbc.to_be_bytes();
        typdefovr_data.extend_from_slice(&6u16.to_be_bytes()); // length: 4 header + 2 data
        typdefovr_data.extend_from_slice(&CCSIDSBC.to_be_bytes());
        typdefovr_data.extend_from_slice(&ccsid_sbc_bytes);
        // CCSIDDBC
        let ccsid_dbc_bytes = ccsid_dbc.to_be_bytes();
        typdefovr_data.extend_from_slice(&6u16.to_be_bytes());
        typdefovr_data.extend_from_slice(&CCSIDDBC.to_be_bytes());
        typdefovr_data.extend_from_slice(&ccsid_dbc_bytes);
        // CCSIDMBC
        let ccsid_mbc_bytes = ccsid_mbc.to_be_bytes();
        typdefovr_data.extend_from_slice(&6u16.to_be_bytes());
        typdefovr_data.extend_from_slice(&CCSIDMBC.to_be_bytes());
        typdefovr_data.extend_from_slice(&ccsid_mbc_bytes);
        ddm.add_code_point(TYPDEFOVR, &typdefovr_data);
    }

    ddm.build()
}

pub fn build_accrdb_luw(rdbnam: &str) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(ACCRDB);
    ddm.add_code_point(RDBNAM, &pad_ebcdic(rdbnam, 18));
    ddm.add_code_point(RDBACCCL, &SQLAM.to_be_bytes());
    ddm.add_ebcdic_string(PRDID, "SQL11014");
    ddm.add_ebcdic_string(TYPDEFNAM, "QTDSQLX86");
    ddm.add_code_point(CRRTKN, &build_luw_crrtkn());

    let mut typdefovr_data = Vec::new();
    typdefovr_data.extend_from_slice(&6u16.to_be_bytes());
    typdefovr_data.extend_from_slice(&CCSIDSBC.to_be_bytes());
    typdefovr_data.extend_from_slice(&DEFAULT_CCSID_SBC.to_be_bytes());
    typdefovr_data.extend_from_slice(&6u16.to_be_bytes());
    typdefovr_data.extend_from_slice(&CCSIDDBC.to_be_bytes());
    typdefovr_data.extend_from_slice(&DEFAULT_CCSID_DBC.to_be_bytes());
    typdefovr_data.extend_from_slice(&6u16.to_be_bytes());
    typdefovr_data.extend_from_slice(&CCSIDMBC.to_be_bytes());
    typdefovr_data.extend_from_slice(&DEFAULT_CCSID_MBC.to_be_bytes());
    ddm.add_code_point(TYPDEFOVR, &typdefovr_data);

    ddm.build()
}

/// Build ACCRDB with default settings.
pub fn build_accrdb_default(rdbnam: &str) -> Vec<u8> {
    build_accrdb(
        rdbnam,
        DEFAULT_PRDID,
        DEFAULT_TYPDEFNAM,
        DEFAULT_CCSID_SBC,
        DEFAULT_CCSID_DBC,
        DEFAULT_CCSID_MBC,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_accrdb() {
        let bytes = build_accrdb_default("TESTDB");
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, ACCRDB);
        let params = obj.parameters();
        assert!(params.iter().any(|p| p.code_point == RDBNAM));
        assert!(params.iter().any(|p| p.code_point == PRDID));
        assert!(!params.iter().any(|p| p.code_point == CRRTKN));
        assert!(params.iter().any(|p| p.code_point == TYPDEFNAM));
        assert!(params.iter().any(|p| p.code_point == TYPDEFOVR));
    }

    #[test]
    fn test_build_accrdb_can_omit_type_definition() {
        let bytes = build_accrdb_with_optional_type_definition(
            "TESTDB",
            DEFAULT_PRDID,
            None,
            DEFAULT_CCSID_SBC,
            DEFAULT_CCSID_DBC,
            DEFAULT_CCSID_MBC,
        );
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        let params = obj.parameters();
        assert!(params.iter().any(|p| p.code_point == RDBNAM));
        assert!(params.iter().any(|p| p.code_point == PRDID));
        assert!(!params.iter().any(|p| p.code_point == TYPDEFNAM));
        assert!(!params.iter().any(|p| p.code_point == TYPDEFOVR));
    }
}
