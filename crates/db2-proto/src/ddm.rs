/// DDM (Distributed Data Management) object construction and parsing.
///
/// DDM structure:
///   - length: u16 BE (total length including this 4-byte header)
///   - code_point: u16 BE
///   - data: remaining bytes, which may contain nested parameters
///
/// Each nested parameter:
///   - length: u16 BE (total length including this 4-byte header)
///   - code_point: u16 BE
///   - data: remaining bytes

use crate::{ProtoError, Result};

/// A parsed DDM parameter (nested within a DDM object).
#[derive(Debug, Clone, PartialEq)]
pub struct DdmParam {
    pub code_point: u16,
    pub data: Vec<u8>,
}

impl DdmParam {
    /// Get data as u16 (big-endian).
    pub fn as_u16(&self) -> Option<u16> {
        if self.data.len() >= 2 {
            Some(u16::from_be_bytes([self.data[0], self.data[1]]))
        } else {
            None
        }
    }

    /// Get data as u32 (big-endian).
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_be_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    /// Get data as i32 (big-endian).
    pub fn as_i32(&self) -> Option<i32> {
        if self.data.len() >= 4 {
            Some(i32::from_be_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    /// Get data as a UTF-8 string.
    pub fn as_utf8(&self) -> Option<String> {
        String::from_utf8(self.data.clone()).ok()
    }

    /// Get data as an EBCDIC 037 decoded string.
    pub fn as_ebcdic(&self) -> String {
        crate::codepage::ebcdic037_to_utf8(&self.data)
    }
}

/// A parsed DDM object.
#[derive(Debug, Clone, PartialEq)]
pub struct DdmObject {
    pub code_point: u16,
    pub data: Vec<u8>,
}

impl DdmObject {
    /// Parse one DDM object from the front of `bytes`.
    /// Returns the parsed object and the number of bytes consumed.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 4 {
            return Err(ProtoError::BufferTooShort {
                expected: 4,
                actual: bytes.len(),
            });
        }
        let length = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let code_point = u16::from_be_bytes([bytes[2], bytes[3]]);

        if length < 4 {
            return Err(ProtoError::Other(format!(
                "DDM length {} is less than minimum 4 for code point 0x{:04X}",
                length, code_point
            )));
        }

        if bytes.len() < length {
            return Err(ProtoError::BufferTooShort {
                expected: length,
                actual: bytes.len(),
            });
        }

        let data = bytes[4..length].to_vec();
        Ok((Self { code_point, data }, length))
    }

    /// Parse nested parameters from this DDM object's data.
    /// Not all DDM objects contain nested parameters; some contain raw data.
    pub fn parameters(&self) -> Vec<DdmParam> {
        let mut params = Vec::new();
        let mut offset = 0;
        while offset + 4 <= self.data.len() {
            let param_len = u16::from_be_bytes([self.data[offset], self.data[offset + 1]]) as usize;
            if param_len < 4 || offset + param_len > self.data.len() {
                break;
            }
            let cp = u16::from_be_bytes([self.data[offset + 2], self.data[offset + 3]]);
            let data = self.data[offset + 4..offset + param_len].to_vec();
            params.push(DdmParam {
                code_point: cp,
                data,
            });
            offset += param_len;
        }
        params
    }

    /// Find a specific parameter by code point.
    pub fn find_param(&self, code_point: u16) -> Option<DdmParam> {
        self.parameters().into_iter().find(|p| p.code_point == code_point)
    }

    /// Total serialized length of this DDM object.
    pub fn total_length(&self) -> usize {
        4 + self.data.len()
    }
}

/// Parse multiple consecutive DDM objects from a byte buffer.
pub fn parse_ddm_objects(bytes: &[u8]) -> Result<Vec<DdmObject>> {
    let mut objects = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            break;
        }
        let (obj, consumed) = DdmObject::parse(&bytes[offset..])?;
        objects.push(obj);
        offset += consumed;
    }
    Ok(objects)
}

/// Builder for constructing DDM objects.
#[derive(Debug, Clone)]
pub struct DdmBuilder {
    code_point: u16,
    data: Vec<u8>,
}

impl DdmBuilder {
    /// Create a new builder for a DDM object with the given command code point.
    pub fn new(code_point: u16) -> Self {
        Self {
            code_point,
            data: Vec::new(),
        }
    }

    /// Add a sub-parameter with a code point and raw data.
    pub fn add_code_point(&mut self, cp: u16, data: &[u8]) -> &mut Self {
        let len = (data.len() + 4) as u16;
        self.data.extend_from_slice(&len.to_be_bytes());
        self.data.extend_from_slice(&cp.to_be_bytes());
        self.data.extend_from_slice(data);
        self
    }

    /// Add a string parameter. Encodes as UTF-8 bytes.
    pub fn add_string(&mut self, cp: u16, s: &str) -> &mut Self {
        self.add_code_point(cp, s.as_bytes())
    }

    /// Add an EBCDIC-encoded string parameter (code page 037).
    pub fn add_ebcdic_string(&mut self, cp: u16, s: &str) -> &mut Self {
        let ebcdic = crate::codepage::utf8_to_ebcdic037(s);
        self.add_code_point(cp, &ebcdic)
    }

    /// Add a u16 parameter (big-endian).
    pub fn add_u16(&mut self, cp: u16, val: u16) -> &mut Self {
        self.add_code_point(cp, &val.to_be_bytes())
    }

    /// Add a u32 parameter (big-endian).
    pub fn add_u32(&mut self, cp: u16, val: u32) -> &mut Self {
        self.add_code_point(cp, &val.to_be_bytes())
    }

    /// Append raw bytes directly to the data section (no sub-code-point header).
    pub fn add_raw(&mut self, data: &[u8]) -> &mut Self {
        self.data.extend_from_slice(data);
        self
    }

    /// Build the complete DDM object as a byte vector.
    /// The result includes the 4-byte DDM header (length + code point).
    pub fn build(&self) -> Vec<u8> {
        let total_len = (self.data.len() + 4) as u16;
        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(&self.code_point.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

/// Build a single DDM parameter as bytes: length(2) + code_point(2) + data.
pub fn build_param(code_point: u16, data: &[u8]) -> Vec<u8> {
    let len = (data.len() + 4) as u16;
    let mut out = Vec::with_capacity(len as usize);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&code_point.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Build a DDM parameter with a u16 value.
pub fn build_param_u16(code_point: u16, value: u16) -> Vec<u8> {
    build_param(code_point, &value.to_be_bytes())
}

/// Build a complete DDM object: length(2) + code_point(2) + payload.
pub fn build_ddm_object(code_point: u16, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() + 4) as u16;
    let mut out = Vec::with_capacity(len as usize);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&code_point.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse() {
        let mut builder = DdmBuilder::new(0x1041);
        builder.add_string(0x115E, "TestClient");
        builder.add_u16(0x11A2, 3);
        let bytes = builder.build();

        let (obj, consumed) = DdmObject::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(obj.code_point, 0x1041);

        let params = obj.parameters();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].code_point, 0x115E);
        assert_eq!(params[0].as_utf8().unwrap(), "TestClient");
        assert_eq!(params[1].code_point, 0x11A2);
        assert_eq!(params[1].as_u16().unwrap(), 3);
    }

    #[test]
    fn test_parse_multiple() {
        let mut b1 = DdmBuilder::new(0x0001);
        b1.add_string(0x0002, "hello");
        let mut b2 = DdmBuilder::new(0x0003);
        b2.add_u32(0x0004, 42);

        let mut data = b1.build();
        data.extend_from_slice(&b2.build());

        let objects = parse_ddm_objects(&data).unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].code_point, 0x0001);
        assert_eq!(objects[1].code_point, 0x0003);
    }
}
