use bytes::BytesMut;
use tracing::{debug, trace};

use crate::config::Config;
use crate::error::Error;
use crate::transport::Transport;
use db2_proto::codepoints;
use db2_proto::ddm::DdmObject;
use db2_proto::dss::{DssReader, DssWriter};

/// Information about the DB2 server, gathered during the authentication handshake.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub product_name: String,
    pub server_release: String,
    pub server_class: String,
    pub manager_levels: Vec<(u16, u16)>,
}

impl Default for ServerInfo {
    fn default() -> Self {
        ServerInfo {
            product_name: String::new(),
            server_release: String::new(),
            server_class: String::new(),
            manager_levels: Vec::new(),
        }
    }
}

/// Perform the full DRDA authentication handshake.
///
/// The flow consists of two exchanges:
/// 1. EXCSAT (chained) + ACCSEC -> EXSATRD + ACCSECRD
/// 2. SECCHK (chained) + ACCRDB -> SECCHKRM + ACCRDBRM
///
/// Returns the server info and the next correlation ID to use.
pub async fn authenticate(
    transport: &mut Transport,
    config: &Config,
) -> Result<(ServerInfo, u16), Error> {
    debug!("Starting DRDA authentication handshake");

    // Phase 1: EXCSAT + ACCSEC
    let excsat_data = db2_proto::commands::excsat::build_excsat_default();
    let accsec_data = db2_proto::commands::accsec::build_accsec_usridpwd(&config.database);

    let mut writer = DssWriter::new(1);
    writer.write_request(&excsat_data, true); // chained
    writer.next_correlation_id();
    writer.write_request(&accsec_data, false); // not chained

    let send_buf = writer.finish();
    transport.write_bytes(&send_buf).await?;
    debug!("Sent EXCSAT + ACCSEC");

    // Read phase 1 responses
    let mut recv_buf = BytesMut::with_capacity(4096);
    transport.read_at_least(&mut recv_buf, 6).await?;

    // Keep reading until we can parse at least 2 frames
    let frames = loop {
        let mut reader = DssReader::new(recv_buf.to_vec());
        let frames = reader.read_all_frames().map_err(|e| Error::Protocol(e.to_string()))?;
        if frames.len() >= 2 {
            let remaining = reader.into_remaining();
            recv_buf = BytesMut::from(remaining.as_slice());
            break frames;
        }
        transport.read_bytes(&mut recv_buf).await?;
    };

    let mut server_info = ServerInfo::default();

    // Parse EXSATRD
    let exsatrd_frame = &frames[0];
    trace!("Received frame 0: type={:?}", exsatrd_frame.header.dss_type);
    let (exsatrd_obj, _) = DdmObject::parse(&exsatrd_frame.payload)
        .map_err(|e| Error::Protocol(e.to_string()))?;

    if exsatrd_obj.code_point == codepoints::EXSATRD {
        let attrs = db2_proto::replies::exsatrd::parse_exsatrd(&exsatrd_obj)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        server_info.product_name = attrs.server_name.unwrap_or_default();
        server_info.server_release = attrs.product_release_level.unwrap_or_default();
        server_info.server_class = attrs.server_class_name.unwrap_or_default();
        server_info.manager_levels = attrs.manager_levels;
    } else {
        return Err(Error::Protocol(format!(
            "Expected EXSATRD (0x{:04X}), got 0x{:04X}",
            codepoints::EXSATRD,
            exsatrd_obj.code_point
        )));
    }

    // Parse ACCSECRD
    let accsecrd_frame = &frames[1];
    trace!("Received frame 1: type={:?}", accsecrd_frame.header.dss_type);
    let (accsecrd_obj, _) = DdmObject::parse(&accsecrd_frame.payload)
        .map_err(|e| Error::Protocol(e.to_string()))?;

    if accsecrd_obj.code_point == codepoints::ACCSECRD {
        let reply = db2_proto::replies::accsecrd::parse_accsecrd(&accsecrd_obj)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        debug!(
            "Server accepted security mechanism: 0x{:04X}",
            reply.security_mechanism
        );
    } else {
        return Err(Error::Protocol(format!(
            "Expected ACCSECRD (0x{:04X}), got 0x{:04X}",
            codepoints::ACCSECRD,
            accsecrd_obj.code_point
        )));
    }

    debug!(
        "Phase 1 complete: server={}, release={}",
        server_info.product_name, server_info.server_release
    );

    // Phase 2: SECCHK + ACCRDB
    let secchk_data =
        db2_proto::commands::secchk::build_secchk_usridpwd(&config.user, &config.password);
    let accrdb_data = db2_proto::commands::accrdb::build_accrdb_default(&config.database);

    let mut writer = DssWriter::new(3);
    writer.write_request(&secchk_data, true); // chained
    writer.next_correlation_id();
    writer.write_request(&accrdb_data, false); // not chained

    let send_buf = writer.finish();
    transport.write_bytes(&send_buf).await?;
    debug!("Sent SECCHK + ACCRDB");

    // Read phase 2 responses
    if recv_buf.len() < 6 {
        transport.read_at_least(&mut recv_buf, 6).await?;
    }

    let frames = loop {
        let mut reader = DssReader::new(recv_buf.to_vec());
        let frames = reader.read_all_frames().map_err(|e| Error::Protocol(e.to_string()))?;
        if frames.len() >= 2 {
            break frames;
        }
        transport.read_bytes(&mut recv_buf).await?;
    };

    // Parse SECCHKRM
    let secchkrm_frame = &frames[0];
    trace!("Received SECCHKRM frame");
    let (secchkrm_obj, _) = DdmObject::parse(&secchkrm_frame.payload)
        .map_err(|e| Error::Protocol(e.to_string()))?;

    if secchkrm_obj.code_point == codepoints::SECCHKRM {
        let reply = db2_proto::replies::secchkrm::parse_secchkrm(&secchkrm_obj)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        if !reply.is_success() {
            return Err(Error::Auth(format!(
                "Security check failed: severity={}, check_code={:?}",
                reply.severity_code, reply.security_check_code
            )));
        }
        debug!("Security check passed");
    } else {
        return Err(Error::Protocol(format!(
            "Expected SECCHKRM (0x{:04X}), got 0x{:04X}",
            codepoints::SECCHKRM,
            secchkrm_obj.code_point
        )));
    }

    // Parse ACCRDBRM
    let accrdbrm_frame = &frames[1];
    trace!("Received ACCRDBRM frame");
    let (accrdbrm_obj, _) = DdmObject::parse(&accrdbrm_frame.payload)
        .map_err(|e| Error::Protocol(e.to_string()))?;

    if accrdbrm_obj.code_point == codepoints::ACCRDBRM {
        let reply = db2_proto::replies::accrdbrm::parse_accrdbrm(&accrdbrm_obj)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        if !reply.is_success() {
            return Err(Error::Connection(format!(
                "Database access failed: severity={}",
                reply.severity_code
            )));
        }
        debug!("Database access granted");
    } else if accrdbrm_obj.code_point == codepoints::RDBNACRM {
        return Err(Error::Connection("Database not accessible".into()));
    } else {
        return Err(Error::Protocol(format!(
            "Expected ACCRDBRM (0x{:04X}), got 0x{:04X}",
            codepoints::ACCRDBRM,
            accrdbrm_obj.code_point
        )));
    }

    debug!("Authentication handshake complete");

    // Next correlation ID is 5 (we used 1-4 during auth)
    Ok((server_info, 5))
}
