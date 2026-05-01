use bytes::BytesMut;
use tracing::{debug, trace, warn};

use crate::config::{Config, SecurityMechanism};
use crate::error::Error;
use crate::transport::Transport;
use db2_proto::codepoints;
use db2_proto::ddm::DdmObject;
use db2_proto::dss::{DssFrame, DssReader, DssWriter};

/// Information about the DB2 server, gathered during the authentication handshake.
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    pub product_name: String,
    pub server_release: String,
    pub server_class: String,
    pub manager_levels: Vec<(u16, u16)>,
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

    // Phase 1: EXCSAT + ACCSEC — negotiate the requested security mechanism.
    let excsat_data = db2_proto::commands::excsat::build_excsat_default();
    let requested_secmec = security_mechanism_code(config.security_mechanism);
    if matches!(
        config.security_mechanism,
        SecurityMechanism::UserPassword | SecurityMechanism::UserOnly
    ) && !config.ssl
    {
        warn!(
            "DRDA security mechanism 0x{:04X} sends credentials without DRDA encryption; enable TLS for production use",
            requested_secmec
        );
    }

    // Generate a DH key pair for encrypted auth and for any server-requested
    // renegotiation back to encrypted credentials.
    let client_private = db2_proto::secmec9::generate_private_key();
    let client_public = db2_proto::secmec9::calculate_public_key(&client_private);

    let accsec_data =
        build_accsec_for_mechanism(requested_secmec, &config.database, &client_public)?;

    let mut writer = DssWriter::new(1);
    writer.write_request(&excsat_data, true); // chained
    writer.set_correlation_id(2);
    writer.write_request(&accsec_data, false); // not chained

    let send_buf = writer.finish();
    transport.write_bytes(&send_buf).await?;
    debug!("Sent EXCSAT + ACCSEC(secmec=0x{requested_secmec:04X})");

    // Read phase 1 responses
    let mut recv_buf = BytesMut::with_capacity(4096);
    transport.read_at_least(&mut recv_buf, 6).await?;

    let frames = loop {
        let mut reader = DssReader::new(recv_buf.to_vec());
        let frames = reader
            .read_all_frames()
            .map_err(|e| Error::Protocol(e.to_string()))?;
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
    let (exsatrd_obj, _) =
        DdmObject::parse(&exsatrd_frame.payload).map_err(|e| Error::Protocol(e.to_string()))?;

    if exsatrd_obj.code_point == codepoints::EXSATRD {
        let attrs = db2_proto::replies::exsatrd::parse_exsatrd(&exsatrd_obj)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        server_info.product_name = attrs.server_name.unwrap_or_default();
        server_info.server_release = attrs.product_release_level.unwrap_or_default();
        server_info.server_class = attrs.server_class_name.unwrap_or_default();
        server_info.manager_levels = attrs.manager_levels;
    } else {
        return Err(Error::Protocol(format!(
            "Expected EXSATRD, got 0x{:04X}",
            exsatrd_obj.code_point
        )));
    }

    // Parse ACCSECRD — get server's accepted mechanism and SECTKN
    let accsecrd_frame = &frames[1];
    let (accsecrd_obj, _) =
        DdmObject::parse(&accsecrd_frame.payload).map_err(|e| Error::Protocol(e.to_string()))?;

    let (accepted_secmec, server_sectkn) = match accsecrd_obj.code_point {
        codepoints::ACCSECRD => {
            let reply = db2_proto::replies::accsecrd::parse_accsecrd(&accsecrd_obj)
                .map_err(|e| Error::Protocol(e.to_string()))?;
            (reply.security_mechanism, reply.security_token)
        }
        codepoints::RDBNACRM | 0x221A => {
            // Some DB2 LUW servers reject an unknown RDB name during ACCSEC
            // instead of waiting until the later ACCRDB phase.
            return Err(Error::Connection(
                "RDB not accessed or database not found".into(),
            ));
        }
        other => {
            return Err(Error::Protocol(format!(
                "Expected ACCSECRD, got 0x{:04X}",
                other
            )));
        }
    };

    debug!(
        "Phase 1 complete: server={}, secmec=0x{:04X}, sectkn={}",
        server_info.product_name,
        accepted_secmec,
        server_sectkn.as_ref().map_or(0, Vec::len)
    );

    // Phase 2: SECCHK + ACCRDB. If the server negotiated a mechanism other
    // than the one we initially requested, send a matching ACCSEC first.
    let renegotiate_security = accepted_secmec != requested_secmec;
    let secchk_data = build_secchk_for_mechanism(
        accepted_secmec,
        server_sectkn.as_deref(),
        &client_private,
        config,
    )?;
    let accrdb_data = db2_proto::commands::accrdb::build_accrdb_default(&config.database);

    let mut writer = DssWriter::new(1);
    if renegotiate_security {
        let accsec_data =
            build_accsec_for_mechanism(accepted_secmec, &config.database, &client_public)?;
        writer.write_request(&accsec_data, true); // chained
        writer.set_correlation_id(2);
    }
    writer.write_request(&secchk_data, true); // chained
    writer.next_correlation_id();
    writer.write_request(&accrdb_data, false); // not chained

    let send_buf = writer.finish();
    transport.write_bytes(&send_buf).await?;
    debug!(
        "Sent {}SECCHK + ACCRDB",
        if renegotiate_security {
            "ACCSEC + "
        } else {
            ""
        }
    );

    // Read phase 2 responses: optional ACCSECRD, SECCHKRM, ACCRDBRM/SQLCARD.
    if recv_buf.len() < 6 {
        transport.read_at_least(&mut recv_buf, 6).await?;
    }

    let min_success_frames = if renegotiate_security { 3 } else { 2 };
    let frames = loop {
        let mut reader = DssReader::new(recv_buf.to_vec());
        let frames = reader
            .read_all_frames()
            .map_err(|e| Error::Protocol(e.to_string()))?;
        if phase2_frames_complete(&frames, min_success_frames)? {
            let _ = reader.into_remaining();
            break frames;
        }

        match transport.read_bytes(&mut recv_buf).await {
            Ok(_) => {}
            Err(Error::Connection(msg))
                if msg.to_lowercase().contains("closed by server") && !frames.is_empty() =>
            {
                break frames;
            }
            Err(Error::Connection(msg)) if msg.to_lowercase().contains("closed by server") => {
                return Err(Error::Connection(
                    "RDB not accessed or database not found".into(),
                ));
            }
            Err(err) => return Err(err),
        }
    };

    // Parse phase 2 replies — DB2 may return only SECCHKRM on auth failure,
    // or close the socket immediately after sending the terminal error frame.
    let mut saw_secchkrm = false;
    let mut found_accrdbrm = false;
    let mut access_error: Option<Error> = None;
    let mut received_code_points = Vec::new();

    for frame in &frames {
        let (obj, _) =
            DdmObject::parse(&frame.payload).map_err(|e| Error::Protocol(e.to_string()))?;
        received_code_points.push(obj.code_point);
        match obj.code_point {
            codepoints::ACCSECRD => {}
            codepoints::SECCHKRM => {
                trace!("Received SECCHKRM frame");
                let reply = db2_proto::replies::secchkrm::parse_secchkrm(&obj)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                saw_secchkrm = true;
                if !reply.is_success() {
                    return Err(Error::Auth(format!(
                        "Security check failed: severity={}, check_code={}, requested_secmec=0x{:04X}, accepted_secmec=0x{:04X}",
                        reply.severity_code,
                        format_security_check_code(reply.security_check_code),
                        requested_secmec,
                        accepted_secmec
                    )));
                }
                debug!("Security check passed");
            }
            codepoints::ACCRDBRM => {
                let reply = db2_proto::replies::accrdbrm::parse_accrdbrm(&obj)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                if !reply.is_success() {
                    access_error = Some(Error::Connection(format!(
                        "Database access failed: severity={}",
                        reply.severity_code
                    )));
                }
                found_accrdbrm = true;
                debug!("Received ACCRDBRM, success={}", reply.is_success());
            }
            codepoints::SQLCARD => {
                let card = db2_proto::replies::sqlcard::parse_sqlcard(&obj)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                if card.is_error() {
                    access_error = Some(Error::Connection(format!(
                        "Database access failed: SQLCODE={}, SQLSTATE={}, {}",
                        card.sqlcode, card.sqlstate, card.sqlerrmc
                    )));
                } else if !found_accrdbrm && card.is_success() {
                    // Some DB2 servers send SQLCARD with sqlcode=0 as a success indicator
                    found_accrdbrm = true;
                }
            }
            codepoints::RDBNACRM => {
                return Err(Error::Connection(
                    "RDB not accessed or database not found".into(),
                ));
            }
            codepoints::PRCCNVRM => {
                return Err(Error::Protocol(format!(
                    "Server returned DRDA protocol error PRCCNVRM during authentication; received {}",
                    format_code_points(&received_code_points)
                )));
            }
            codepoints::CMDNSPRM | codepoints::PRMNSPRM | codepoints::VALNSPRM => {
                return Err(Error::Protocol(format!(
                    "Server rejected an authentication parameter with {}: {}; received {}",
                    code_point_name(obj.code_point),
                    format_reply_detail(&obj),
                    format_code_points(&received_code_points)
                )));
            }
            codepoints::SYNTAXRM | codepoints::CMDCHKRM | codepoints::OBJNSPRM => {
                return Err(Error::Protocol(format!(
                    "Server rejected an authentication command with {}: {}; received {}",
                    code_point_name(obj.code_point),
                    format_reply_detail(&obj),
                    format_code_points(&received_code_points)
                )));
            }
            codepoints::SQLERRRM => {
                let reply = db2_proto::replies::sqlerrrm::parse_sqlerrrm(&obj)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                access_error = Some(Error::Protocol(format!(
                    "Server returned SQLERRRM during authentication: severity={}",
                    reply.severity_code
                )));
            }
            other => {
                debug!(
                    "Received unexpected code point 0x{:04X} during ACCRDB",
                    other
                );
            }
        }
    }

    if !saw_secchkrm {
        return Err(Error::Protocol(format!(
            "No SECCHKRM received during authentication; received {}",
            format_code_points(&received_code_points)
        )));
    }
    if let Some(err) = access_error {
        return Err(err);
    }
    if !found_accrdbrm {
        return Err(Error::Protocol(
            "No ACCRDBRM or success SQLCARD received during database access".into(),
        ));
    }
    debug!("Database access granted");

    // Post-auth: connection is established

    debug!("Authentication handshake complete");

    // Reset correlation ID for SQL operations
    Ok((server_info, 1))
}

fn security_mechanism_code(security_mechanism: SecurityMechanism) -> u16 {
    match security_mechanism {
        SecurityMechanism::EncryptedUserPassword => codepoints::SECMEC_EUSRIDPWD,
        SecurityMechanism::EncryptedPassword => codepoints::SECMEC_USRENCPWD,
        SecurityMechanism::UserPassword => codepoints::SECMEC_USRIDPWD,
        SecurityMechanism::UserOnly => codepoints::SECMEC_USRIDONL,
    }
}

fn build_accsec_for_mechanism(
    security_mechanism: u16,
    rdbnam: &str,
    client_public: &[u8],
) -> Result<Vec<u8>, Error> {
    match security_mechanism {
        codepoints::SECMEC_EUSRIDPWD
        | codepoints::SECMEC_USRENCPWD
        | codepoints::SECMEC_USRIDPWD
        | codepoints::SECMEC_USRIDONL => {
            let mut ddm = db2_proto::ddm::DdmBuilder::new(codepoints::ACCSEC);
            ddm.add_u16(codepoints::SECMEC, security_mechanism);
            ddm.add_code_point(codepoints::RDBNAM, &db2_proto::codepage::pad_rdbnam(rdbnam));
            if matches!(
                security_mechanism,
                codepoints::SECMEC_EUSRIDPWD | codepoints::SECMEC_USRENCPWD
            ) {
                ddm.add_code_point(codepoints::SECTKN, client_public);
            }
            Ok(ddm.build())
        }
        other => Err(Error::Auth(format!(
            "Unsupported DRDA security mechanism 0x{other:04X}"
        ))),
    }
}

fn build_secchk_for_mechanism(
    security_mechanism: u16,
    server_sectkn: Option<&[u8]>,
    client_private: &[u8],
    config: &Config,
) -> Result<Vec<u8>, Error> {
    match security_mechanism {
        codepoints::SECMEC_EUSRIDPWD => {
            let server_sectkn = server_sectkn.ok_or_else(|| {
                Error::Protocol(
                    "ACCSECRD selected encrypted authentication but did not include SECTKN".into(),
                )
            })?;
            db2_proto::commands::secchk::build_secchk_eusridpwd(
                &config.database,
                &config.user,
                &config.password,
                server_sectkn,
                client_private,
            )
            .map_err(Error::from)
        }
        codepoints::SECMEC_USRENCPWD => {
            let server_sectkn = server_sectkn.ok_or_else(|| {
                Error::Protocol(
                    "ACCSECRD selected encrypted password authentication but did not include SECTKN"
                        .into(),
                )
            })?;
            db2_proto::commands::secchk::build_secchk_usencpwd(
                &config.database,
                &config.user,
                &config.password,
                server_sectkn,
                client_private,
            )
            .map_err(Error::from)
        }
        codepoints::SECMEC_USRIDPWD => Ok(db2_proto::commands::secchk::build_secchk_usridpwd(
            &config.database,
            &config.user,
            &config.password,
        )),
        codepoints::SECMEC_USRIDONL => {
            let mut ddm = db2_proto::ddm::DdmBuilder::new(codepoints::SECCHK);
            ddm.add_u16(codepoints::SECMEC, codepoints::SECMEC_USRIDONL);
            ddm.add_code_point(
                codepoints::USRID,
                &db2_proto::codepage::utf8_to_ebcdic037(&config.user),
            );
            Ok(ddm.build())
        }
        other => Err(Error::Auth(format!(
            "Server selected unsupported DRDA security mechanism 0x{other:04X}"
        ))),
    }
}

fn phase2_frames_complete(frames: &[DssFrame], min_success_frames: usize) -> Result<bool, Error> {
    if frames.len() >= min_success_frames {
        return Ok(true);
    }

    let mut saw_secchkrm_success = false;
    let mut saw_access_reply = false;

    for frame in frames {
        let (obj, _) =
            DdmObject::parse(&frame.payload).map_err(|e| Error::Protocol(e.to_string()))?;
        match obj.code_point {
            codepoints::SECCHKRM => {
                let reply = db2_proto::replies::secchkrm::parse_secchkrm(&obj)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                if !reply.is_success() {
                    return Ok(true);
                }
                saw_secchkrm_success = true;
            }
            codepoints::ACCRDBRM => saw_access_reply = true,
            codepoints::RDBNACRM
            | codepoints::PRCCNVRM
            | codepoints::SYNTAXRM
            | codepoints::CMDNSPRM
            | codepoints::PRMNSPRM
            | codepoints::VALNSPRM
            | codepoints::CMDCHKRM
            | codepoints::OBJNSPRM
            | codepoints::SQLERRRM => return Ok(true),
            codepoints::SQLCARD => {
                let card = db2_proto::replies::sqlcard::parse_sqlcard(&obj)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                if card.is_error() {
                    return Ok(true);
                }
                if card.is_success() {
                    saw_access_reply = true;
                }
            }
            _ => {}
        }
    }

    Ok(saw_secchkrm_success && saw_access_reply)
}

fn format_security_check_code(code: Option<u8>) -> String {
    match code {
        Some(0x00) => "0x00 (success)".into(),
        Some(0x01) => "0x01 (security mechanism not supported)".into(),
        Some(0x0A) => "0x0A (security service non-retryable error)".into(),
        Some(0x0B) => "0x0B (security token missing or invalid)".into(),
        Some(0x0E) => "0x0E (password expired)".into(),
        Some(0x0F) => "0x0F (user id or password invalid)".into(),
        Some(0x10) => "0x10 (password missing)".into(),
        Some(0x12) => "0x12 (user id missing)".into(),
        Some(0x13) => "0x13 (user id or password invalid)".into(),
        Some(0x14) => "0x14 (user id revoked)".into(),
        Some(0x15) => "0x15 (new password invalid)".into(),
        Some(other) => format!("0x{other:02X}"),
        None => "unknown".into(),
    }
}

fn format_code_points(code_points: &[u16]) -> String {
    if code_points.is_empty() {
        return "none".into();
    }

    code_points
        .iter()
        .map(|cp| format!("{}(0x{cp:04X})", code_point_name(*cp)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_reply_detail(obj: &DdmObject) -> String {
    let mut details = Vec::new();

    if let Some(severity) = obj.find_param(codepoints::SVRCOD).and_then(|p| p.as_u16()) {
        details.push(format!("severity={severity}"));
    }

    if let Some(code_point) = obj.find_param(codepoints::CODPNT).and_then(|p| p.as_u16()) {
        details.push(format!(
            "parameter={}(0x{code_point:04X})",
            code_point_name(code_point)
        ));
    }

    if details.is_empty() {
        format!("data_len={}", obj.data.len())
    } else {
        details.join(", ")
    }
}

fn code_point_name(code_point: u16) -> &'static str {
    match code_point {
        codepoints::EXCSAT => "EXCSAT",
        codepoints::EXSATRD => "EXSATRD",
        codepoints::ACCSEC => "ACCSEC",
        codepoints::ACCSECRD => "ACCSECRD",
        codepoints::SECCHK => "SECCHK",
        codepoints::SECCHKRM => "SECCHKRM",
        codepoints::ACCRDB => "ACCRDB",
        codepoints::ACCRDBRM => "ACCRDBRM",
        codepoints::CODPNT => "CODPNT",
        codepoints::SVRCOD => "SVRCOD",
        codepoints::SECMEC => "SECMEC",
        codepoints::SECTKN => "SECTKN",
        codepoints::USRID => "USRID",
        codepoints::PASSWORD => "PASSWORD",
        codepoints::RDBNAM => "RDBNAM",
        codepoints::SQLCARD => "SQLCARD",
        codepoints::RDBNACRM => "RDBNACRM",
        codepoints::PRCCNVRM => "PRCCNVRM",
        codepoints::SYNTAXRM => "SYNTAXRM",
        codepoints::CMDNSPRM => "CMDNSPRM",
        codepoints::PRMNSPRM => "PRMNSPRM",
        codepoints::VALNSPRM => "VALNSPRM",
        codepoints::CMDCHKRM => "CMDCHKRM",
        codepoints::OBJNSPRM => "OBJNSPRM",
        codepoints::SQLERRRM => "SQLERRRM",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db2_proto::dss::{DssFlags, DssHeader, DssType};

    fn reply_frame(payload: Vec<u8>) -> DssFrame {
        DssFrame {
            header: DssHeader {
                length: (payload.len() + 6) as u16,
                dss_type: DssType::Reply,
                flags: DssFlags::none(),
                correlation_id: 1,
            },
            payload,
        }
    }

    #[test]
    fn valnsprm_ends_phase2_read() {
        let mut builder = db2_proto::ddm::DdmBuilder::new(codepoints::VALNSPRM);
        builder.add_u16(codepoints::SVRCOD, codepoints::SRVCOD_ERROR);
        builder.add_u16(codepoints::CODPNT, codepoints::SECMEC);

        let frames = vec![reply_frame(builder.build())];

        assert!(phase2_frames_complete(&frames, 2).unwrap());
    }

    #[test]
    fn reply_detail_includes_rejected_parameter() {
        let mut builder = db2_proto::ddm::DdmBuilder::new(codepoints::VALNSPRM);
        builder.add_u16(codepoints::SVRCOD, codepoints::SRVCOD_ERROR);
        builder.add_u16(codepoints::CODPNT, codepoints::SECTKN);
        let bytes = builder.build();
        let (obj, _) = DdmObject::parse(&bytes).unwrap();

        assert_eq!(
            format_reply_detail(&obj),
            "severity=8, parameter=SECTKN(0x11DC)"
        );
    }

    #[test]
    fn security_check_code_names_include_zos_auth_failures() {
        assert_eq!(
            format_security_check_code(Some(0x13)),
            "0x13 (user id or password invalid)"
        );
        assert_eq!(
            format_security_check_code(Some(0x14)),
            "0x14 (user id revoked)"
        );
        assert_eq!(
            format_security_check_code(Some(0x0B)),
            "0x0B (security token missing or invalid)"
        );
    }

    #[test]
    fn accsec_includes_sectkn_only_for_encrypted_auth() {
        let public_key = [0xAA; 32];
        let encrypted =
            build_accsec_for_mechanism(codepoints::SECMEC_EUSRIDPWD, "DSNDB04", &public_key)
                .unwrap();
        let (encrypted_obj, _) = DdmObject::parse(&encrypted).unwrap();
        assert!(encrypted_obj.find_param(codepoints::SECTKN).is_some());

        let encrypted_password =
            build_accsec_for_mechanism(codepoints::SECMEC_USRENCPWD, "DSNDB04", &public_key)
                .unwrap();
        let (encrypted_password_obj, _) = DdmObject::parse(&encrypted_password).unwrap();
        assert!(encrypted_password_obj
            .find_param(codepoints::SECTKN)
            .is_some());

        let clear = build_accsec_for_mechanism(codepoints::SECMEC_USRIDPWD, "DSNDB04", &public_key)
            .unwrap();
        let (clear_obj, _) = DdmObject::parse(&clear).unwrap();
        assert!(clear_obj.find_param(codepoints::SECTKN).is_none());
    }
}
