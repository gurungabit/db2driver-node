/// Protocol-level unit tests for DSS (Data Stream Structure) parsing and serialization.
/// These tests do NOT require a DB2 server -- they operate purely on byte buffers.
use db2_proto::dss::*;

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

#[test]
fn test_dss_header_parse() {
    // 6-byte valid DSS header: length=0x000E (14), magic=0xD0, format=0x01 (Request),
    // correlation_id=0x0001
    let bytes: [u8; 6] = [0x00, 0x0E, 0xD0, 0x01, 0x00, 0x01];
    let header = DssHeader::parse(&bytes).expect("should parse valid header");
    assert_eq!(header.length, 14);
    assert_eq!(header.dss_type, DssType::Request);
    assert!(!header.flags.chained);
    assert!(!header.flags.same_correlation);
    assert_eq!(header.correlation_id, 1);
}

#[test]
fn test_dss_header_serialize() {
    let header = DssHeader {
        length: 42,
        dss_type: DssType::Reply,
        flags: DssFlags::none(),
        correlation_id: 7,
    };
    let bytes = header.serialize();
    // length
    assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 42);
    // magic
    assert_eq!(bytes[2], DSS_MAGIC);
    // format = Reply(2) | no flags = 0x02
    assert_eq!(bytes[3], 0x02);
    // correlation_id
    assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 7);
}

#[test]
fn test_dss_bad_magic() {
    let bytes: [u8; 6] = [0x00, 0x0E, 0xAA, 0x01, 0x00, 0x01]; // magic=0xAA, not 0xD0
    let err = DssHeader::parse(&bytes).unwrap_err();
    match err {
        db2_proto::ProtoError::InvalidMagic(m) => assert_eq!(m, 0xAA),
        other => panic!("Expected InvalidMagic, got {:?}", other),
    }
}

#[test]
fn test_dss_too_short() {
    let bytes: [u8; 3] = [0x00, 0x0E, 0xD0];
    let err = DssHeader::parse(&bytes).unwrap_err();
    match err {
        db2_proto::ProtoError::BufferTooShort { expected, actual } => {
            assert_eq!(expected, DSS_HEADER_LEN);
            assert_eq!(actual, 3);
        }
        other => panic!("Expected BufferTooShort, got {:?}", other),
    }
}

#[test]
fn test_dss_chaining_flag() {
    // format byte 0x41 = chained request (0x40 | 0x01)
    let bytes: [u8; 6] = [0x00, 0x0A, 0xD0, 0x41, 0x00, 0x02];
    let header = DssHeader::parse(&bytes).expect("should parse chained header");
    assert_eq!(header.dss_type, DssType::Request);
    assert!(header.flags.chained);
    assert!(!header.flags.same_correlation);
    assert_eq!(header.correlation_id, 2);
}

#[test]
fn test_dss_same_correlation_flag() {
    // format byte 0x13 = Object(3) | same_correlation(0x10)
    let bytes: [u8; 6] = [0x00, 0x08, 0xD0, 0x13, 0x00, 0x05];
    let header = DssHeader::parse(&bytes).expect("should parse");
    assert_eq!(header.dss_type, DssType::Object);
    assert!(header.flags.same_correlation);
    assert!(!header.flags.chained);
}

// ---------------------------------------------------------------------------
// Roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_dss_roundtrip() {
    let original = DssHeader {
        length: 256,
        dss_type: DssType::Object,
        flags: DssFlags {
            chained: true,
            continue_on_error: false,
            same_correlation: false,
        },
        correlation_id: 1234,
    };
    let bytes = original.serialize();
    let parsed = DssHeader::parse(&bytes).expect("roundtrip parse");
    assert_eq!(parsed.length, original.length);
    assert_eq!(parsed.dss_type, original.dss_type);
    assert_eq!(parsed.flags.chained, original.flags.chained);
    assert_eq!(parsed.correlation_id, original.correlation_id);
}

// ---------------------------------------------------------------------------
// Writer / Reader roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_dss_writer_reader_roundtrip() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let mut writer = DssWriter::new(1);
    writer.write_request(&payload, false);
    let data = writer.finish();

    let mut reader = DssReader::new(data);
    let frame = reader.next_frame().unwrap().expect("should have a frame");
    assert_eq!(frame.header.dss_type, DssType::Request);
    assert!(!frame.header.flags.chained);
    assert_eq!(frame.header.correlation_id, 1);
    assert_eq!(frame.payload, payload);
}

#[test]
fn test_dss_writer_chained() {
    let payload1 = vec![0x01, 0x02];
    let payload2 = vec![0x03, 0x04];

    let mut writer = DssWriter::new(1);
    writer.write_request(&payload1, true); // chained
    writer.write_object(&payload2, false); // not chained (last in chain)
    let data = writer.finish();

    let mut reader = DssReader::new(data);
    let frames = reader.read_all_frames().unwrap();
    assert_eq!(frames.len(), 2);
    assert!(frames[0].header.flags.chained);
    assert!(!frames[1].header.flags.chained);
    assert_eq!(frames[0].payload, payload1);
    assert_eq!(frames[1].payload, payload2);
}

// ---------------------------------------------------------------------------
// Fixture-based test (skipped if no fixture data)
// ---------------------------------------------------------------------------

#[test]
fn test_parse_captured_handshake() {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/protocol/fixtures/excsat_request.bin"
    );
    let data = match std::fs::read(fixture_path) {
        Ok(d) if !d.is_empty() => d,
        _ => {
            eprintln!("Skipping fixture test: no data at {}", fixture_path);
            return;
        }
    };
    let mut reader = DssReader::new(data);
    let frames = reader.read_all_frames().expect("fixture should parse");
    assert!(
        !frames.is_empty(),
        "fixture should contain at least one frame"
    );
    // The first frame of an EXCSAT exchange is a Request DSS
    assert_eq!(frames[0].header.dss_type, DssType::Request);
}
