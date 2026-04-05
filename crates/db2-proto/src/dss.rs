/// DSS (Data Stream Structure) framing for DRDA protocol.
///
/// A DSS header is 6 bytes:
///   - length: u16 BE (total length of DSS segment including header)
///   - magic:  u8 (always 0xD0)
///   - format: u8 (encodes DSS type and flags)
///   - correlation_id: u16 BE
///
/// Format byte layout:
///   Bits 0-3: DSS type (1=Request, 2=Reply, 3=Object, 4=Communication)
///   Bit 4:    same correlation (continue previous correlation)
///   Bit 5:    (reserved)
///   Bit 6:    chained (more DSS segments follow in this chain)
///   Bit 7:    (reserved)
///
/// In practice the observed format bytes:
///   0x01 = Request, not chained
///   0x41 = Request, chained
///   0x02 = Reply
///   0x03 = Object, not chained
///   0x43 = Object, chained
///   0x13 = Object, same correlation (continuation)

use crate::{ProtoError, Result};

pub const DSS_MAGIC: u8 = 0xD0;
pub const DSS_HEADER_LEN: usize = 6;
/// Maximum length of a single DSS segment.
pub const DSS_MAX_SEGMENT_LEN: usize = 32767;

/// DSS type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DssType {
    Request,       // 1
    Reply,         // 2
    Object,        // 3
    Communication, // 4
}

impl DssType {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b & 0x0F {
            1 => Ok(DssType::Request),
            2 => Ok(DssType::Reply),
            3 => Ok(DssType::Object),
            4 => Ok(DssType::Communication),
            other => Err(ProtoError::InvalidDssType(other)),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            DssType::Request => 1,
            DssType::Reply => 2,
            DssType::Object => 3,
            DssType::Communication => 4,
        }
    }
}

/// Flags extracted from the DSS format byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DssFlags {
    pub chained: bool,
    pub continue_on_error: bool,
    pub same_correlation: bool,
}

impl DssFlags {
    pub fn none() -> Self {
        Self {
            chained: false,
            continue_on_error: false,
            same_correlation: false,
        }
    }

    pub fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.chained {
            b |= 0x40;
        }
        if self.continue_on_error {
            b |= 0x20;
        }
        if self.same_correlation {
            b |= 0x10;
        }
        b
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            chained: (b & 0x40) != 0,
            continue_on_error: (b & 0x20) != 0,
            same_correlation: (b & 0x10) != 0,
        }
    }
}

/// A parsed DSS header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DssHeader {
    pub length: u16,
    pub dss_type: DssType,
    pub flags: DssFlags,
    pub correlation_id: u16,
}

impl DssHeader {
    /// Parse a DSS header from a 6-byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DSS_HEADER_LEN {
            return Err(ProtoError::BufferTooShort {
                expected: DSS_HEADER_LEN,
                actual: data.len(),
            });
        }
        let length = u16::from_be_bytes([data[0], data[1]]);
        let magic = data[2];
        if magic != DSS_MAGIC {
            return Err(ProtoError::InvalidMagic(magic));
        }
        let format = data[3];
        let dss_type = DssType::from_byte(format)?;
        let flags = DssFlags::from_byte(format);
        let correlation_id = u16::from_be_bytes([data[4], data[5]]);
        Ok(Self {
            length,
            dss_type,
            flags,
            correlation_id,
        })
    }

    /// Serialize this DSS header to 6 bytes.
    pub fn serialize(&self) -> [u8; DSS_HEADER_LEN] {
        let len_bytes = self.length.to_be_bytes();
        let format = self.dss_type.to_byte() | self.flags.to_byte();
        let corr = self.correlation_id.to_be_bytes();
        [len_bytes[0], len_bytes[1], DSS_MAGIC, format, corr[0], corr[1]]
    }
}

/// Writer that builds DSS-framed messages around DDM payloads.
///
/// Handles chaining multiple DDM objects in a single request chain,
/// and DSS continuation for payloads > 32767 bytes.
#[derive(Debug, Clone)]
pub struct DssWriter {
    correlation_id: u16,
    buffer: Vec<u8>,
}

impl DssWriter {
    pub fn new(initial_correlation_id: u16) -> Self {
        Self {
            correlation_id: initial_correlation_id,
            buffer: Vec::new(),
        }
    }

    /// Return the accumulated bytes and reset the internal buffer.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }

    /// Get a reference to the current buffer.
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Current correlation ID.
    pub fn correlation_id(&self) -> u16 {
        self.correlation_id
    }

    /// Increment and return next correlation ID.
    pub fn next_correlation_id(&mut self) -> u16 {
        self.correlation_id = self.correlation_id.wrapping_add(1);
        self.correlation_id
    }

    /// Write a single DDM payload wrapped in one or more DSS segments.
    /// If `chained` is true, the chained flag is set on the first DSS segment.
    pub fn write_dss(
        &mut self,
        dss_type: DssType,
        chained: bool,
        payload: &[u8],
    ) {
        let total = payload.len() + DSS_HEADER_LEN;

        if total <= DSS_MAX_SEGMENT_LEN {
            // Single segment
            let header = DssHeader {
                length: total as u16,
                dss_type,
                flags: DssFlags {
                    chained,
                    continue_on_error: false,
                    same_correlation: false,
                },
                correlation_id: self.correlation_id,
            };
            self.buffer.extend_from_slice(&header.serialize());
            self.buffer.extend_from_slice(payload);
        } else {
            // Multi-segment continuation
            let mut offset = 0usize;
            let mut first = true;
            while offset < payload.len() {
                let max_payload = DSS_MAX_SEGMENT_LEN - DSS_HEADER_LEN;
                let remaining = payload.len() - offset;
                let is_last = remaining <= max_payload;
                let chunk_len = if is_last { remaining } else { max_payload };
                let seg_len = chunk_len + DSS_HEADER_LEN;

                let flags = DssFlags {
                    chained: if first { chained } else { false },
                    continue_on_error: false,
                    same_correlation: !first,
                };

                let header = DssHeader {
                    length: seg_len as u16,
                    dss_type: if first { dss_type } else { DssType::Object },
                    flags,
                    correlation_id: self.correlation_id,
                };

                self.buffer.extend_from_slice(&header.serialize());
                self.buffer.extend_from_slice(&payload[offset..offset + chunk_len]);

                offset += chunk_len;
                first = false;
            }
        }
    }

    /// Convenience: write a Request DSS.
    pub fn write_request(&mut self, payload: &[u8], chained: bool) {
        self.write_dss(DssType::Request, chained, payload);
    }

    /// Convenience: write an Object DSS (used for SQLSTT, SQLDTA, etc.).
    pub fn write_object(&mut self, payload: &[u8], chained: bool) {
        self.write_dss(DssType::Object, chained, payload);
    }
}

/// Build a DSS Request frame around a payload.
pub fn build_dss_request(correlation_id: u16, chained: bool, payload: &[u8]) -> Vec<u8> {
    let mut writer = DssWriter::new(correlation_id);
    writer.write_request(payload, chained);
    writer.finish()
}

/// Build a DSS Object frame around a payload.
pub fn build_dss_object(correlation_id: u16, chained: bool, payload: &[u8]) -> Vec<u8> {
    let mut writer = DssWriter::new(correlation_id);
    writer.write_object(payload, chained);
    writer.finish()
}

/// A parsed DSS frame: header + payload bytes.
#[derive(Debug, Clone)]
pub struct DssFrame {
    pub header: DssHeader,
    pub payload: Vec<u8>,
}

/// Reader that parses DSS frames from a byte buffer.
///
/// Handles DSS continuation segments transparently by concatenating
/// continuation segment payloads into a single logical frame.
#[derive(Debug, Clone)]
pub struct DssReader {
    buffer: Vec<u8>,
    position: usize,
}

impl DssReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            buffer: data,
            position: 0,
        }
    }

    /// Add more data to the internal buffer.
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Return remaining bytes in the buffer.
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }

    /// Check if we have enough data for at least one DSS header.
    pub fn has_complete_frame(&self) -> bool {
        if self.remaining() < DSS_HEADER_LEN {
            return false;
        }
        let len = u16::from_be_bytes([
            self.buffer[self.position],
            self.buffer[self.position + 1],
        ]) as usize;
        self.remaining() >= len
    }

    /// Parse the next DSS frame, handling continuation segments.
    /// Returns None if not enough data is available.
    pub fn next_frame(&mut self) -> Result<Option<DssFrame>> {
        if !self.has_complete_frame() {
            return Ok(None);
        }

        let header = DssHeader::parse(&self.buffer[self.position..])?;
        let seg_len = header.length as usize;

        if self.remaining() < seg_len {
            return Ok(None);
        }

        let payload_start = self.position + DSS_HEADER_LEN;
        let payload_end = self.position + seg_len;
        let mut payload = self.buffer[payload_start..payload_end].to_vec();
        let first_header = header.clone();
        self.position += seg_len;

        // Handle continuation: if next segment has same_correlation flag set,
        // it's a continuation of this DSS.
        loop {
            if self.remaining() < DSS_HEADER_LEN {
                break;
            }
            let peek = DssHeader::parse(&self.buffer[self.position..])?;
            if !peek.flags.same_correlation {
                break;
            }
            let cont_len = peek.length as usize;
            if self.remaining() < cont_len {
                // Not enough data yet — we can't partially consume, so put back.
                // In practice, the caller should buffer more data and retry.
                break;
            }
            let cont_start = self.position + DSS_HEADER_LEN;
            let cont_end = self.position + cont_len;
            payload.extend_from_slice(&self.buffer[cont_start..cont_end]);
            self.position += cont_len;
        }

        Ok(Some(DssFrame {
            header: first_header,
            payload,
        }))
    }

    /// Parse all available frames.
    pub fn read_all_frames(&mut self) -> Result<Vec<DssFrame>> {
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    /// Consume the reader and return any unprocessed bytes.
    pub fn into_remaining(self) -> Vec<u8> {
        if self.position >= self.buffer.len() {
            Vec::new()
        } else {
            self.buffer[self.position..].to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let hdr = DssHeader {
            length: 100,
            dss_type: DssType::Request,
            flags: DssFlags {
                chained: true,
                continue_on_error: false,
                same_correlation: false,
            },
            correlation_id: 1,
        };
        let bytes = hdr.serialize();
        assert_eq!(bytes[2], DSS_MAGIC);
        assert_eq!(bytes[3], 0x41); // chained request
        let parsed = DssHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.length, 100);
        assert_eq!(parsed.dss_type, DssType::Request);
        assert!(parsed.flags.chained);
        assert_eq!(parsed.correlation_id, 1);
    }

    #[test]
    fn test_writer_reader_roundtrip() {
        let payload = vec![0x00, 0x08, 0x10, 0x41, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut writer = DssWriter::new(1);
        writer.write_request(&payload, false);
        let data = writer.finish();

        let mut reader = DssReader::new(data);
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame.header.dss_type, DssType::Request);
        assert_eq!(frame.payload, payload);
    }
}
