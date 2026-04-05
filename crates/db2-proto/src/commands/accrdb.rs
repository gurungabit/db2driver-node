/// Build ACCRDB (Access RDB) command.

use crate::codepoints::*;
use crate::codepage::pad_rdbnam;
use crate::ddm::DdmBuilder;

/// Default product identifier (mimics JCC driver).
pub const DEFAULT_PRDID: &str = "JCC04200";

/// Default type definition name for x86/Linux/Windows.
pub const DEFAULT_TYPDEFNAM: &str = "QTDSQLX86";

/// Default CCSID values.
pub const DEFAULT_CCSID_SBC: u16 = 1208; // UTF-8 single-byte
pub const DEFAULT_CCSID_DBC: u16 = 1200; // UTF-16
pub const DEFAULT_CCSID_MBC: u16 = 1208; // UTF-8 mixed-byte

/// Build an ACCRDB DDM command.
///
/// Parameters:
///   - rdbnam: Database name
///   - prdid: Product specific identifier (e.g., "JCC04200")
///   - typdefnam: Type definition name (e.g., "QTDSQLX86")
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
    let mut ddm = DdmBuilder::new(ACCRDB);
    ddm.add_code_point(RDBNAM, &pad_rdbnam(rdbnam));
    ddm.add_code_point(RDBACCCL, &SQLAM.to_be_bytes());

    // PRDID is encoded as EBCDIC
    ddm.add_ebcdic_string(PRDID, prdid);

    // TYPDEFNAM is encoded as EBCDIC
    ddm.add_ebcdic_string(TYPDEFNAM, typdefnam);

    // TYPDEFOVR contains CCSID sub-parameters
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
        assert!(params.iter().any(|p| p.code_point == TYPDEFNAM));
        assert!(params.iter().any(|p| p.code_point == TYPDEFOVR));
    }
}
