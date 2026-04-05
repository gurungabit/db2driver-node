//! Build OPNQRY (Open Query) command.
use crate::codepoints::*;
use crate::ddm::DdmBuilder;

/// Default query block size (32KB).
pub const DEFAULT_QRYBLKSZ: u32 = 32767;

/// Build an OPNQRY DDM command.
///
/// Parameters:
///   - pkgnamcsn: Pre-built PKGNAMCSN bytes
///   - qryblksz: Query block size (max bytes per fetch block)
///   - maxblkext: Maximum number of extra blocks (-1 for unlimited)
///   - qryprctyp: Query protocol type (FIXROWPRC or LMTBLKPRC)
///   - nbrrow: Number of rows to fetch (0 = server decides)
///   - sqldta: Optional SQL parameter data (for parameterized queries)
pub fn build_opnqry(
    pkgnamcsn: &[u8],
    qryblksz: u32,
    maxblkext: Option<i16>,
    qryprctyp: u16,
    nbrrow: Option<u32>,
    sqldta: Option<&[u8]>,
) -> Vec<u8> {
    let mut ddm = DdmBuilder::new(OPNQRY);
    ddm.add_code_point(PKGNAMCSN, pkgnamcsn);
    ddm.add_u32(QRYBLKSZ, qryblksz);
    ddm.add_u16(QRYPRCTYP, qryprctyp);

    if let Some(ext) = maxblkext {
        ddm.add_u16(MAXBLKEXT, ext as u16);
    }

    if let Some(rows) = nbrrow {
        ddm.add_u32(NBRROW, rows);
    }

    if let Some(data) = sqldta {
        ddm.add_code_point(SQLDTA, data);
    }

    ddm.build()
}

/// Build OPNQRY with typical defaults for a SELECT query.
pub fn build_opnqry_default(pkgnamcsn: &[u8]) -> Vec<u8> {
    build_opnqry(
        pkgnamcsn,
        DEFAULT_QRYBLKSZ,
        Some(-1),
        QRYPRCTYP_LMTBLKPRC,
        Some(100),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::build_default_pkgnamcsn;
    use crate::ddm::DdmObject;

    #[test]
    fn test_build_opnqry() {
        let pkgnamcsn = build_default_pkgnamcsn("TESTDB", 1);
        let bytes = build_opnqry_default(&pkgnamcsn);
        let (obj, _) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(obj.code_point, OPNQRY);
        let params = obj.parameters();
        assert!(params.iter().any(|p| p.code_point == QRYBLKSZ));
        assert!(params.iter().any(|p| p.code_point == QRYPRCTYP));
    }
}
