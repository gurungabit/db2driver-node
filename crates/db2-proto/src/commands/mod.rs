pub mod accrdb;
pub mod accsec;
pub mod clsqry;
pub mod cntqry;
pub mod excsat;
pub mod excsqlimm;
pub mod excsqlstt;
pub mod opnqry;
pub mod prpsqlstt;
pub mod rdbcmm;
pub mod rdbrllbck;
pub mod secchk;
pub mod sqlstt;

use crate::codepage::pad_ebcdic;

/// Default package collection ID (EBCDIC padded to 18 bytes).
pub const DEFAULT_RDBCOLID: &str = "NULLID";

/// Default package ID for dynamic SQL (EBCDIC padded to 18 bytes).
pub const DEFAULT_PKGID: &str = "SYSSH200";

/// Default consistency token (8 bytes of zeros for dynamic SQL).
pub const DEFAULT_PKGCNSTKN: [u8; 8] = [0x00; 8];

/// Build a PKGNAMCSN (Package Name, Consistency Token, Section Number) byte sequence.
///
/// Format:
///   - RDBNAM: 18 bytes EBCDIC padded
///   - RDBCOLID: 18 bytes EBCDIC padded
///   - PKGID: 18 bytes EBCDIC padded
///   - PKGCNSTKN: 8 bytes (consistency token)
///   - PKGSN: 2 bytes (section number, big-endian u16)
pub fn build_pkgnamcsn(
    rdbnam: &str,
    rdbcolid: &str,
    pkgid: &str,
    pkgcnstkn: &[u8; 8],
    section_number: u16,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&pad_ebcdic(rdbnam, 18));
    data.extend_from_slice(&pad_ebcdic(rdbcolid, 18));
    data.extend_from_slice(&pad_ebcdic(pkgid, 18));
    data.extend_from_slice(pkgcnstkn);
    data.extend_from_slice(&section_number.to_be_bytes());
    data
}

/// Build a PKGNAMCSN with default collection ID, package ID, and consistency token.
pub fn build_default_pkgnamcsn(rdbnam: &str, section_number: u16) -> Vec<u8> {
    build_pkgnamcsn(
        rdbnam,
        DEFAULT_RDBCOLID,
        DEFAULT_PKGID,
        &DEFAULT_PKGCNSTKN,
        section_number,
    )
}
