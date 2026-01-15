//! ExtProc Dynamic Module Implementation
//!
//! This module implements an External Processor (ExtProc) filter using Envoy's Dynamic Modules
//! framework. It provides request/response header and body processing, immediate response
//! handling, mode override support, and comprehensive error handling.
//!
//! # Wire Protocol
//!
//! Uses gRPC over HTTP/2 with 5-byte framing: 1 byte compression + 4 bytes message length.

use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::time::Instant;

// ============================================================================
// Protobuf Wire Format Constants
// ============================================================================

/// Protobuf wire types.
mod wire_type {
  pub const VARINT: u8 = 0;
  pub const LEN: u8 = 2;
}

/// gRPC header size (1 byte compression + 4 bytes length).
pub const GRPC_HEADER_SIZE: usize = 5;

/// Initial capacity for encoding buffers to reduce allocations.
const ENCODE_BUFFER_INITIAL_CAPACITY: usize = 256;

// ============================================================================
// Protobuf Encoding/Decoding Utilities
// ============================================================================

/// Encodes a varint (unsigned).
pub fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
  while value > 0x7F {
    buf.push((value as u8 & 0x7F) | 0x80);
    value >>= 7;
  }
  buf.push(value as u8);
}

/// Decodes a varint, returns (value, bytes_consumed).
pub fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
  let mut value: u64 = 0;
  let mut shift = 0;
  for (i, &byte) in data.iter().enumerate() {
    value |= ((byte & 0x7F) as u64) << shift;
    if byte & 0x80 == 0 {
      return Some((value, i + 1));
    }
    shift += 7;
    if shift > 63 {
      return None;
    }
  }
  None
}

/// Encodes a length-delimited field.
fn encode_length_delimited(field_num: u32, data: &[u8], buf: &mut Vec<u8>) {
  let tag = (field_num << 3) | wire_type::LEN as u32;
  encode_varint(tag as u64, buf);
  encode_varint(data.len() as u64, buf);
  buf.extend_from_slice(data);
}

/// Encodes a bool field.
fn encode_bool(field_num: u32, value: bool, buf: &mut Vec<u8>) {
  if value {
    let tag = (field_num << 3) | wire_type::VARINT as u32;
    encode_varint(tag as u64, buf);
    buf.push(1);
  }
}

/// Encodes a u32 field.
fn encode_u32(field_num: u32, value: u32, buf: &mut Vec<u8>) {
  if value != 0 {
    let tag = (field_num << 3) | wire_type::VARINT as u32;
    encode_varint(tag as u64, buf);
    encode_varint(value as u64, buf);
  }
}

/// Encodes a string field.
fn encode_string(field_num: u32, value: &str, buf: &mut Vec<u8>) {
  if !value.is_empty() {
    encode_length_delimited(field_num, value.as_bytes(), buf);
  }
}

/// Encodes a bytes field.
fn encode_bytes(field_num: u32, value: &[u8], buf: &mut Vec<u8>) {
  if !value.is_empty() {
    encode_length_delimited(field_num, value, buf);
  }
}

/// Encodes a message with gRPC framing.
pub fn encode_grpc_message(message: &[u8]) -> Vec<u8> {
  let mut buf = Vec::with_capacity(GRPC_HEADER_SIZE + message.len());
  buf.push(0); // No compression.
  buf.extend_from_slice(&(message.len() as u32).to_be_bytes());
  buf.extend_from_slice(message);
  buf
}

/// Decodes a gRPC frame, returns (compressed, payload).
pub fn decode_grpc_frame(data: &[u8]) -> Option<(bool, &[u8])> {
  if data.len() < GRPC_HEADER_SIZE {
    return None;
  }
  let compressed = data[0] != 0;
  let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
  if data.len() < GRPC_HEADER_SIZE + len {
    return None;
  }
  Some((
    compressed,
    &data[GRPC_HEADER_SIZE .. GRPC_HEADER_SIZE + len],
  ))
}

// ============================================================================
// Processing Modes
// ============================================================================

/// Header send mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HeaderSendMode {
  #[default]
  Default = 0,
  Send    = 1,
  Skip    = 2,
}

/// Body send mode.
///
/// - `None`: Do not send the body to the external processor.
/// - `Streamed`: Stream body chunks to the processor as they arrive.
/// - `Buffered`: Buffer the entire body before sending to the processor.
/// - `BufferedPartial`: Buffer up to the limit, then send what we have.
/// - `FullDuplexStreamed`: Stream body chunks without waiting for responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BodySendMode {
  #[default]
  None               = 0,
  Streamed           = 1,
  Buffered           = 2,
  BufferedPartial    = 3,
  FullDuplexStreamed = 4,
}

/// Processing mode configuration.
#[derive(Clone, Debug, Default)]
pub struct ProcessingMode {
  pub request_header_mode: HeaderSendMode,
  pub response_header_mode: HeaderSendMode,
  pub request_body_mode: BodySendMode,
  pub response_body_mode: BodySendMode,
}

// ============================================================================
// Message Types
// ============================================================================

/// Header value.
#[derive(Clone, Debug, Default)]
pub struct HeaderValue {
  pub key: String,
  pub raw_value: Vec<u8>,
}

impl HeaderValue {
  pub fn encode(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_string(1, &self.key, &mut buf);
    encode_bytes(3, &self.raw_value, &mut buf);
    buf
  }
}

/// HTTP headers message.
#[derive(Clone, Debug, Default)]
pub struct HttpHeaders {
  pub headers: Vec<HeaderValue>,
  pub end_of_stream: bool,
}

impl HttpHeaders {
  pub fn encode(&self) -> Vec<u8> {
    self.encode_with_capacity()
  }

  fn encode_with_capacity(&self) -> Vec<u8> {
    // Estimate capacity: ~50 bytes per header on average.
    let estimated_size = self.headers.len() * 50 + 10;
    let mut headers_map = Vec::with_capacity(estimated_size);
    for h in &self.headers {
      encode_length_delimited(1, &h.encode(), &mut headers_map);
    }
    let mut buf = Vec::with_capacity(headers_map.len() + 10);
    if !headers_map.is_empty() {
      encode_length_delimited(1, &headers_map, &mut buf);
    }
    encode_bool(3, self.end_of_stream, &mut buf);
    buf
  }
}

/// HTTP body message.
#[derive(Clone, Debug, Default)]
pub struct HttpBody {
  pub body: Vec<u8>,
  pub end_of_stream: bool,
}

impl HttpBody {
  pub fn encode(&self) -> Vec<u8> {
    self.encode_with_capacity()
  }

  fn encode_with_capacity(&self) -> Vec<u8> {
    // Pre-allocate buffer with body size + overhead for field tags.
    let mut buf = Vec::with_capacity(self.body.len() + 10);
    encode_bytes(1, &self.body, &mut buf);
    encode_bool(2, self.end_of_stream, &mut buf);
    buf
  }
}

/// Header mutation.
#[derive(Clone, Debug, Default)]
pub struct HeaderMutation {
  pub set_headers: Vec<HeaderValue>,
  pub remove_headers: Vec<String>,
}

impl HeaderMutation {
  fn decode(data: &[u8]) -> Option<Self> {
    let mut mutation = HeaderMutation::default();
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      match (field_num, wire_type) {
        (1, 2) => {
          // HeaderValueOption.
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          if let Some(header) =
            Self::decode_header_value_option(&data[offset .. offset + len as usize])
          {
            mutation.set_headers.push(header);
          }
          offset += len as usize;
        },
        (2, 2) => {
          // Remove header (string).
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          let s = String::from_utf8_lossy(&data[offset .. offset + len as usize]).to_string();
          mutation.remove_headers.push(s);
          offset += len as usize;
        },
        _ => {
          // Skip unknown field.
          if wire_type == 2 {
            let (len, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed + len as usize;
          } else if wire_type == 0 {
            let (_, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed;
          }
        },
      }
    }
    Some(mutation)
  }

  fn decode_header_value_option(data: &[u8]) -> Option<HeaderValue> {
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      if field_num == 1 && wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
        return Self::decode_header_value(&data[offset .. offset + len as usize]);
      } else if wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed + len as usize;
      } else if wire_type == 0 {
        let (_, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
      }
    }
    None
  }

  fn decode_header_value(data: &[u8]) -> Option<HeaderValue> {
    let mut header = HeaderValue::default();
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      if wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
        match field_num {
          1 => {
            header.key = String::from_utf8_lossy(&data[offset .. offset + len as usize]).to_string()
          },
          3 => header.raw_value = data[offset .. offset + len as usize].to_vec(),
          _ => {},
        }
        offset += len as usize;
      } else if wire_type == 0 {
        let (_, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
      }
    }
    Some(header)
  }
}

/// Body mutation.
#[derive(Clone, Debug, Default)]
pub struct BodyMutation {
  pub body: Option<Vec<u8>>,
  pub clear_body: bool,
}

impl BodyMutation {
  fn decode(data: &[u8]) -> Option<Self> {
    let mut mutation = BodyMutation::default();
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      match (field_num, wire_type) {
        (1, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          mutation.body = Some(data[offset .. offset + len as usize].to_vec());
          offset += len as usize;
        },
        (2, 0) => {
          let (val, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          mutation.clear_body = val != 0;
        },
        _ => {
          if wire_type == 2 {
            let (len, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed + len as usize;
          } else if wire_type == 0 {
            let (_, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed;
          }
        },
      }
    }
    Some(mutation)
  }
}

/// Response status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ResponseStatus {
  #[default]
  Continue           = 0,
  ContinueAndReplace = 1,
}

/// Common response.
#[derive(Clone, Debug, Default)]
pub struct CommonResponse {
  pub status: ResponseStatus,
  pub header_mutation: Option<HeaderMutation>,
  pub body_mutation: Option<BodyMutation>,
  pub clear_route_cache: bool,
}

impl CommonResponse {
  fn decode(data: &[u8]) -> Option<Self> {
    let mut resp = CommonResponse::default();
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      match (field_num, wire_type) {
        (1, 0) => {
          let (val, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.status = if val == 1 {
            ResponseStatus::ContinueAndReplace
          } else {
            ResponseStatus::Continue
          };
        },
        (2, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.header_mutation = HeaderMutation::decode(&data[offset .. offset + len as usize]);
          offset += len as usize;
        },
        (3, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.body_mutation = BodyMutation::decode(&data[offset .. offset + len as usize]);
          offset += len as usize;
        },
        (5, 0) => {
          let (val, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.clear_route_cache = val != 0;
        },
        _ => {
          if wire_type == 2 {
            let (len, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed + len as usize;
          } else if wire_type == 0 {
            let (_, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed;
          }
        },
      }
    }
    Some(resp)
  }
}

/// Headers response.
#[derive(Clone, Debug, Default)]
pub struct HeadersResponse {
  pub response: Option<CommonResponse>,
}

/// Body response.
#[derive(Clone, Debug, Default)]
pub struct BodyResponse {
  pub response: Option<CommonResponse>,
}

/// Immediate response.
#[derive(Clone, Debug, Default)]
pub struct ImmediateResponse {
  pub status_code: u32,
  pub headers: Option<HeaderMutation>,
  pub body: Vec<u8>,
  pub grpc_status: Option<u32>,
  pub details: String,
}

impl ImmediateResponse {
  fn decode(data: &[u8]) -> Option<Self> {
    let mut resp = ImmediateResponse::default();
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      match (field_num, wire_type) {
        (1, 2) => {
          // HttpStatus message.
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          if let Some(code) = Self::decode_http_status(&data[offset .. offset + len as usize]) {
            resp.status_code = code;
          }
          offset += len as usize;
        },
        (2, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.headers = HeaderMutation::decode(&data[offset .. offset + len as usize]);
          offset += len as usize;
        },
        (3, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.body = data[offset .. offset + len as usize].to_vec();
          offset += len as usize;
        },
        (4, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          if let Some(status) = Self::decode_grpc_status(&data[offset .. offset + len as usize]) {
            resp.grpc_status = Some(status);
          }
          offset += len as usize;
        },
        (5, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.details =
            String::from_utf8_lossy(&data[offset .. offset + len as usize]).to_string();
          offset += len as usize;
        },
        _ => {
          if wire_type == 2 {
            let (len, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed + len as usize;
          } else if wire_type == 0 {
            let (_, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed;
          }
        },
      }
    }
    Some(resp)
  }

  fn decode_http_status(data: &[u8]) -> Option<u32> {
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      if field_num == 1 && wire_type == 0 {
        let (val, _) = decode_varint(&data[offset ..])?;
        return Some(val as u32);
      } else if wire_type == 0 {
        let (_, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
      } else if wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed + len as usize;
      }
    }
    None
  }

  fn decode_grpc_status(data: &[u8]) -> Option<u32> {
    Self::decode_http_status(data) // Same structure.
  }
}

/// Streamed immediate response for sending responses in chunks.
#[derive(Clone, Debug, Default)]
pub struct StreamedImmediateResponse {
  pub status_code: Option<u32>,
  pub headers: Option<HeaderMutation>,
  pub body_chunk: Vec<u8>,
  pub end_of_stream: bool,
  pub grpc_status: Option<u32>,
  pub details: String,
}

impl StreamedImmediateResponse {
  fn decode(data: &[u8]) -> Option<Self> {
    let mut resp = StreamedImmediateResponse::default();
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      match (field_num, wire_type) {
        (1, 2) => {
          // HttpStatus message.
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          let end = offset + len as usize;
          if let Some(code) = ImmediateResponse::decode_http_status(&data[offset .. end]) {
            resp.status_code = Some(code);
          }
          offset = end;
        },
        (2, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.headers = HeaderMutation::decode(&data[offset .. offset + len as usize]);
          offset += len as usize;
        },
        (3, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.body_chunk = data[offset .. offset + len as usize].to_vec();
          offset += len as usize;
        },
        (4, 0) => {
          let (val, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.end_of_stream = val != 0;
        },
        (5, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          let end = offset + len as usize;
          if let Some(status) = ImmediateResponse::decode_grpc_status(&data[offset .. end]) {
            resp.grpc_status = Some(status);
          }
          offset = end;
        },
        (6, 2) => {
          let (len, consumed) = decode_varint(&data[offset ..])?;
          offset += consumed;
          resp.details =
            String::from_utf8_lossy(&data[offset .. offset + len as usize]).to_string();
          offset += len as usize;
        },
        _ => {
          if wire_type == 2 {
            let (len, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed + len as usize;
          } else if wire_type == 0 {
            let (_, consumed) = decode_varint(&data[offset ..])?;
            offset += consumed;
          }
        },
      }
    }
    Some(resp)
  }
}

/// Processing response type.
#[derive(Clone, Debug)]
pub enum ProcessingResponseType {
  RequestHeaders(HeadersResponse),
  ResponseHeaders(HeadersResponse),
  RequestBody(BodyResponse),
  ResponseBody(BodyResponse),
  ImmediateResponse(ImmediateResponse),
  StreamedImmediateResponse(StreamedImmediateResponse),
}

/// Processing response.
#[derive(Clone, Debug)]
pub struct ProcessingResponse {
  pub response: Option<ProcessingResponseType>,
  pub mode_override: Option<ProcessingMode>,
  pub override_message_timeout_ms: Option<u64>,
}

impl ProcessingResponse {
  pub fn decode(data: &[u8]) -> Option<Self> {
    let mut resp = ProcessingResponse {
      response: None,
      mode_override: None,
      override_message_timeout_ms: None,
    };
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      if wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
        let field_data = &data[offset .. offset + len as usize];
        offset += len as usize;

        match field_num {
          1 => {
            let common = Self::decode_headers_response(field_data);
            resp.response = Some(ProcessingResponseType::RequestHeaders(HeadersResponse {
              response: common,
            }));
          },
          2 => {
            let common = Self::decode_headers_response(field_data);
            resp.response = Some(ProcessingResponseType::ResponseHeaders(HeadersResponse {
              response: common,
            }));
          },
          3 => {
            let common = Self::decode_body_response(field_data);
            resp.response = Some(ProcessingResponseType::RequestBody(BodyResponse {
              response: common,
            }));
          },
          4 => {
            let common = Self::decode_body_response(field_data);
            resp.response = Some(ProcessingResponseType::ResponseBody(BodyResponse {
              response: common,
            }));
          },
          7 => {
            if let Some(imm) = ImmediateResponse::decode(field_data) {
              resp.response = Some(ProcessingResponseType::ImmediateResponse(imm));
            }
          },
          8 => {
            if let Some(streamed) = StreamedImmediateResponse::decode(field_data) {
              resp.response = Some(ProcessingResponseType::StreamedImmediateResponse(streamed));
            }
          },
          9 => {
            resp.mode_override = Self::decode_processing_mode(field_data);
          },
          10 => {
            // Override message timeout (Duration proto - field 1 is seconds, field 2 is nanos).
            resp.override_message_timeout_ms = Self::decode_duration_ms(field_data);
          },
          _ => {},
        }
      } else if wire_type == 0 {
        let (_, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
      }
    }
    Some(resp)
  }

  fn decode_duration_ms(data: &[u8]) -> Option<u64> {
    let mut seconds: u64 = 0;
    let mut nanos: u64 = 0;
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      if wire_type == 0 {
        let (val, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
        match field_num {
          1 => seconds = val,
          2 => nanos = val,
          _ => {},
        }
      } else if wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed + len as usize;
      }
    }
    Some(seconds * 1000 + nanos / 1_000_000)
  }

  fn decode_headers_response(data: &[u8]) -> Option<CommonResponse> {
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      if field_num == 1 && wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
        return CommonResponse::decode(&data[offset .. offset + len as usize]);
      } else if wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed + len as usize;
      } else if wire_type == 0 {
        let (_, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
      }
    }
    Some(CommonResponse::default())
  }

  fn decode_body_response(data: &[u8]) -> Option<CommonResponse> {
    Self::decode_headers_response(data) // Same structure.
  }

  fn decode_processing_mode(data: &[u8]) -> Option<ProcessingMode> {
    let mut mode = ProcessingMode::default();
    let mut offset = 0;
    while offset < data.len() {
      let (tag_val, consumed) = decode_varint(&data[offset ..])?;
      offset += consumed;
      let field_num = (tag_val >> 3) as u32;
      let wire_type = (tag_val & 0x7) as u8;

      if wire_type == 0 {
        let (val, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed;
        match field_num {
          1 => mode.request_header_mode = Self::to_header_mode(val as i32),
          2 => mode.response_header_mode = Self::to_header_mode(val as i32),
          3 => mode.request_body_mode = Self::to_body_mode(val as i32),
          4 => mode.response_body_mode = Self::to_body_mode(val as i32),
          _ => {},
        }
      } else if wire_type == 2 {
        let (len, consumed) = decode_varint(&data[offset ..])?;
        offset += consumed + len as usize;
      }
    }
    Some(mode)
  }

  fn to_header_mode(val: i32) -> HeaderSendMode {
    match val {
      1 => HeaderSendMode::Send,
      2 => HeaderSendMode::Skip,
      _ => HeaderSendMode::Default,
    }
  }

  fn to_body_mode(val: i32) -> BodySendMode {
    match val {
      1 => BodySendMode::Streamed,
      2 => BodySendMode::Buffered,
      3 => BodySendMode::BufferedPartial,
      4 => BodySendMode::FullDuplexStreamed,
      _ => BodySendMode::None,
    }
  }
}

// ============================================================================
// ProcessingRequest Encoding
// ============================================================================

/// Request type for ProcessingRequest.
pub enum ProcessingRequestType {
  RequestHeaders(HttpHeaders),
  ResponseHeaders(HttpHeaders),
  RequestBody(HttpBody),
  ResponseBody(HttpBody),
}

/// Processing request.
pub struct ProcessingRequest {
  pub request: ProcessingRequestType,
  pub observability_mode: bool,
}

impl ProcessingRequest {
  pub fn encode(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ENCODE_BUFFER_INITIAL_CAPACITY);
    match &self.request {
      ProcessingRequestType::RequestHeaders(h) => {
        encode_length_delimited(2, &h.encode_with_capacity(), &mut buf)
      },
      ProcessingRequestType::ResponseHeaders(h) => {
        encode_length_delimited(3, &h.encode_with_capacity(), &mut buf)
      },
      ProcessingRequestType::RequestBody(b) => {
        encode_length_delimited(4, &b.encode_with_capacity(), &mut buf)
      },
      ProcessingRequestType::ResponseBody(b) => {
        encode_length_delimited(5, &b.encode_with_capacity(), &mut buf)
      },
    }
    encode_bool(10, self.observability_mode, &mut buf);
    buf
  }
}

// ============================================================================
// ExtProc Filter Configuration
// ============================================================================

/// Route cache action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RouteCacheAction {
  #[default]
  Default = 0,
  Clear   = 1,
  Retain  = 2,
}

/// ExtProc filter configuration.
#[derive(Clone, Debug)]
pub struct ExtProcConfig {
  pub cluster_name: String,
  pub processing_mode: ProcessingMode,
  pub message_timeout_ms: u64,
  pub max_message_timeout_ms: u64,
  pub allow_mode_override: bool,
  pub failure_mode_allow: bool,
  pub status_on_error: u32,
  pub disable_immediate_response: bool,
  pub route_cache_action: RouteCacheAction,
  pub observability_mode: bool,
  pub max_buffered_body_bytes: usize,
}

impl ExtProcConfig {
  /// Returns the maximum size for buffered body data.
  pub fn max_buffered_body_size(&self) -> usize {
    self.max_buffered_body_bytes
  }
}

/// Default buffer limit for body data (1MB).
const DEFAULT_MAX_BUFFERED_BODY_BYTES: usize = 1024 * 1024;

impl Default for ExtProcConfig {
  fn default() -> Self {
    Self {
      cluster_name: String::new(),
      processing_mode: ProcessingMode {
        request_header_mode: HeaderSendMode::Send,
        response_header_mode: HeaderSendMode::Send,
        request_body_mode: BodySendMode::None,
        response_body_mode: BodySendMode::None,
      },
      message_timeout_ms: 10000,
      max_message_timeout_ms: 0,
      allow_mode_override: true,
      failure_mode_allow: false,
      status_on_error: 500,
      disable_immediate_response: false,
      route_cache_action: RouteCacheAction::Default,
      observability_mode: false,
      max_buffered_body_bytes: DEFAULT_MAX_BUFFERED_BODY_BYTES,
    }
  }
}

// ============================================================================
// ExtProc Statistics
// ============================================================================

/// Statistics for ExtProc filter operations.
#[derive(Clone, Debug, Default)]
pub struct ExtProcStats {
  pub streams_started: u64,
  pub stream_msgs_sent: u64,
  pub stream_msgs_received: u64,
  pub spurious_msgs_received: u64,
  pub streams_closed: u64,
  pub streams_failed: u64,
  pub failure_mode_allowed: u64,
  pub message_timeouts: u64,
  pub rejected_header_mutations: u64,
  pub override_message_timeout_received: u64,
  pub override_message_timeout_ignored: u64,
  pub clear_route_cache_ignored: u64,
  pub immediate_responses_sent: u64,
}

// ============================================================================
// ExtProc Logging Info
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct GrpcCallStats {
  pub latency_us: u64,
  pub call_status: u32,
}

/// Body-specific gRPC call stats for streamed mode.
#[derive(Clone, Debug, Default)]
pub struct GrpcCallBodyStats {
  pub call_count: u32,
  pub last_call_status: u32,
  pub total_latency_us: u64,
  pub max_latency_us: u64,
  pub min_latency_us: u64,
}

impl GrpcCallBodyStats {
  pub fn new() -> Self {
    Self {
      call_count: 0,
      last_call_status: 0,
      total_latency_us: 0,
      max_latency_us: 0,
      min_latency_us: u64::MAX,
    }
  }

  pub fn record(&mut self, latency_us: u64, status: u32) {
    self.call_count += 1;
    self.last_call_status = status;
    self.total_latency_us += latency_us;
    if latency_us > self.max_latency_us {
      self.max_latency_us = latency_us;
    }
    if latency_us < self.min_latency_us {
      self.min_latency_us = latency_us;
    }
  }
}

#[derive(Clone, Debug, Default)]
pub struct ExtProcLoggingInfo {
  pub request_headers: Option<GrpcCallStats>,
  pub response_headers: Option<GrpcCallStats>,
  pub request_body: Option<GrpcCallBodyStats>,
  pub response_body: Option<GrpcCallBodyStats>,
  pub failed_open: bool,
  pub error_details: Option<String>,
  pub bytes_sent: u64,
  pub bytes_received: u64,
}

impl ExtProcLoggingInfo {
  pub fn serialize(&self) -> Vec<u8> {
    let mut result = String::new();
    if let Some(ref stats) = self.request_headers {
      result.push_str(&format!(
        "request_headers_latency_us={}\n",
        stats.latency_us
      ));
    }
    if let Some(ref stats) = self.response_headers {
      result.push_str(&format!(
        "response_headers_latency_us={}\n",
        stats.latency_us
      ));
    }
    if let Some(ref stats) = self.request_body {
      if stats.call_count > 0 {
        result.push_str(&format!("request_body_call_count={}\n", stats.call_count));
        result.push_str(&format!(
          "request_body_total_latency_us={}\n",
          stats.total_latency_us
        ));
      }
    }
    if let Some(ref stats) = self.response_body {
      if stats.call_count > 0 {
        result.push_str(&format!("response_body_call_count={}\n", stats.call_count));
        result.push_str(&format!(
          "response_body_total_latency_us={}\n",
          stats.total_latency_us
        ));
      }
    }
    if self.failed_open {
      result.push_str("failed_open=true\n");
    }
    if let Some(ref details) = self.error_details {
      result.push_str(&format!("error_details={}\n", details));
    }
    if self.bytes_sent > 0 {
      result.push_str(&format!("bytes_sent={}\n", self.bytes_sent));
    }
    if self.bytes_received > 0 {
      result.push_str(&format!("bytes_received={}\n", self.bytes_received));
    }
    result.into_bytes()
  }
}

// ============================================================================
// Callback State
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CallbackState {
  #[default]
  Idle,
  HeadersCallback,
  BodyCallback,
}

// ============================================================================
// ExtProc Filter Implementation
// ============================================================================

pub struct ExtProcFilterConfig {
  config: ExtProcConfig,
}

impl ExtProcFilterConfig {
  pub fn new(config: ExtProcConfig) -> Self {
    Self { config }
  }
}

impl<EHF: EnvoyHttpFilter> HttpFilterConfig<EHF> for ExtProcFilterConfig {
  fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
    Box::new(ExtProcFilter::new(self.config.clone()))
  }
}

pub struct ExtProcFilter {
  config: ExtProcConfig,
  effective_mode: ProcessingMode,
  decoding_state: CallbackState,
  encoding_state: CallbackState,
  stream_handle: Option<u64>,
  stats: ExtProcStats,
  logging_info: ExtProcLoggingInfo,
  request_start_time: Option<Instant>,
  response_start_time: Option<Instant>,
  request_body_start_time: Option<Instant>,
  response_body_start_time: Option<Instant>,
  response_buffer: Vec<u8>,
  in_encoding_phase: bool,
  processing_complete: bool,
  buffered_request_body: Vec<u8>,
  buffered_response_body: Vec<u8>,
  failure_mode_allow: bool,
  request_body_chunks_sent: u32,
  response_body_chunks_sent: u32,
}

impl ExtProcFilter {
  pub fn new(config: ExtProcConfig) -> Self {
    let effective_mode = config.processing_mode.clone();
    let failure_mode_allow = config.failure_mode_allow;
    Self {
      config,
      effective_mode,
      decoding_state: CallbackState::Idle,
      encoding_state: CallbackState::Idle,
      stream_handle: None,
      stats: ExtProcStats::default(),
      logging_info: ExtProcLoggingInfo::default(),
      request_start_time: None,
      response_start_time: None,
      request_body_start_time: None,
      response_body_start_time: None,
      response_buffer: Vec::new(),
      in_encoding_phase: false,
      processing_complete: false,
      buffered_request_body: Vec::new(),
      buffered_response_body: Vec::new(),
      failure_mode_allow,
      request_body_chunks_sent: 0,
      response_body_chunks_sent: 0,
    }
  }

  fn should_send_headers(&self, is_request: bool) -> bool {
    let mode = if is_request {
      self.effective_mode.request_header_mode
    } else {
      self.effective_mode.response_header_mode
    };
    matches!(mode, HeaderSendMode::Send | HeaderSendMode::Default)
  }

  fn body_mode(&self, is_request: bool) -> BodySendMode {
    if is_request {
      self.effective_mode.request_body_mode
    } else {
      self.effective_mode.response_body_mode
    }
  }

  fn open_grpc_stream<EHF: EnvoyHttpFilter>(&mut self, envoy_filter: &mut EHF) -> bool {
    let (result, handle) = envoy_filter.start_http_stream(
      &self.config.cluster_name,
      vec![
        (
          ":path",
          b"/envoy.service.ext_proc.v3.ExternalProcessor/Process",
        ),
        (":method", b"POST"),
        ("host", self.config.cluster_name.as_bytes()),
        ("content-type", b"application/grpc"),
        ("te", b"trailers"),
      ],
      None,
      false,
      self.config.message_timeout_ms,
    );

    if result != abi::envoy_dynamic_module_type_http_callout_init_result::Success {
      self.stats.streams_failed += 1;
      return false;
    }

    self.stream_handle = Some(handle);
    self.stats.streams_started += 1;
    true
  }

  fn send_request<EHF: EnvoyHttpFilter>(
    &mut self,
    envoy_filter: &mut EHF,
    request: &ProcessingRequest,
  ) -> bool {
    let Some(handle) = self.stream_handle else {
      return false;
    };

    let encoded = request.encode();
    let grpc_message = encode_grpc_message(&encoded);
    self.logging_info.bytes_sent += grpc_message.len() as u64;
    self.stats.stream_msgs_sent += 1;

    unsafe { envoy_filter.send_http_stream_data(handle, &grpc_message, false) }
  }

  fn collect_headers<EHF: EnvoyHttpFilter>(
    envoy_filter: &EHF,
    is_request: bool,
    end_of_stream: bool,
  ) -> HttpHeaders {
    let headers_list = if is_request {
      envoy_filter.get_request_headers()
    } else {
      envoy_filter.get_response_headers()
    };

    let headers = headers_list
      .into_iter()
      .map(|(k, v)| HeaderValue {
        key: String::from_utf8_lossy(k.as_slice()).to_string(),
        raw_value: v.as_slice().to_vec(),
      })
      .collect();

    HttpHeaders {
      headers,
      end_of_stream,
    }
  }

  fn apply_header_mutations<EHF: EnvoyHttpFilter>(
    envoy_filter: &mut EHF,
    mutation: &HeaderMutation,
    is_request: bool,
  ) {
    for header in &mutation.set_headers {
      if is_request {
        envoy_filter.set_request_header(&header.key, &header.raw_value);
      } else {
        envoy_filter.set_response_header(&header.key, &header.raw_value);
      }
    }
    for key in &mutation.remove_headers {
      if is_request {
        envoy_filter.remove_request_header(key);
      } else {
        envoy_filter.remove_response_header(key);
      }
    }
  }

  fn handle_processing_response<EHF: EnvoyHttpFilter>(
    &mut self,
    envoy_filter: &mut EHF,
    response: ProcessingResponse,
  ) {
    // Check if this is a timeout override message (no response type).
    if let Some(timeout_ms) = response.override_message_timeout_ms {
      self.handle_override_message_timeout(timeout_ms);
      return;
    }

    self.stats.stream_msgs_received += 1;

    if self.config.allow_mode_override {
      if let Some(mode) = response.mode_override {
        self.effective_mode = mode;
      }
    }

    let Some(resp_type) = response.response else {
      return;
    };

    match resp_type {
      ProcessingResponseType::RequestHeaders(h) => {
        self.handle_headers_response(envoy_filter, h, true)
      },
      ProcessingResponseType::ResponseHeaders(h) => {
        self.handle_headers_response(envoy_filter, h, false)
      },
      ProcessingResponseType::RequestBody(b) => self.handle_body_response(envoy_filter, b, true),
      ProcessingResponseType::ResponseBody(b) => self.handle_body_response(envoy_filter, b, false),
      ProcessingResponseType::ImmediateResponse(imm) => {
        self.handle_immediate_response(envoy_filter, imm)
      },
      ProcessingResponseType::StreamedImmediateResponse(streamed) => {
        self.handle_streamed_immediate_response(envoy_filter, streamed)
      },
    }
  }

  fn handle_override_message_timeout(&mut self, timeout_ms: u64) {
    // Validate timeout is within configured range.
    if timeout_ms < 1 || timeout_ms > self.config.max_message_timeout_ms {
      self.stats.override_message_timeout_ignored += 1;
      return;
    }
    self.stats.override_message_timeout_received += 1;
    // Note: In a full implementation, this would reset the message timer.
    // For the dynamic module, timeout management is handled by the SDK.
  }

  fn handle_streamed_immediate_response<EHF: EnvoyHttpFilter>(
    &mut self,
    envoy_filter: &mut EHF,
    streamed: StreamedImmediateResponse,
  ) {
    if self.config.disable_immediate_response {
      return;
    }

    // For the first chunk, send the response with status and headers.
    if let Some(status_code) = streamed.status_code {
      let mut header_strings: Vec<(String, Vec<u8>)> = Vec::new();
      if let Some(ref mutation) = streamed.headers {
        for h in &mutation.set_headers {
          header_strings.push((h.key.clone(), h.raw_value.clone()));
        }
      }

      let headers: Vec<(&str, &[u8])> = header_strings
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_slice()))
        .collect();
      let body = if streamed.body_chunk.is_empty() {
        None
      } else {
        Some(streamed.body_chunk.as_slice())
      };
      let details = if streamed.details.is_empty() {
        None
      } else {
        Some(streamed.details.as_str())
      };

      envoy_filter.send_response(status_code, headers, body, details);
      self.stats.immediate_responses_sent += 1;
    }

    if streamed.end_of_stream {
      self.processing_complete = true;
    }
  }

  fn handle_headers_response<EHF: EnvoyHttpFilter>(
    &mut self,
    envoy_filter: &mut EHF,
    headers_resp: HeadersResponse,
    is_request: bool,
  ) {
    if is_request {
      if let Some(start) = self.request_start_time.take() {
        self.logging_info.request_headers = Some(GrpcCallStats {
          latency_us: start.elapsed().as_micros() as u64,
          call_status: 0,
        });
      }
      self.decoding_state = CallbackState::Idle;
    } else {
      if let Some(start) = self.response_start_time.take() {
        self.logging_info.response_headers = Some(GrpcCallStats {
          latency_us: start.elapsed().as_micros() as u64,
          call_status: 0,
        });
      }
      self.encoding_state = CallbackState::Idle;
    }

    if let Some(common) = headers_resp.response {
      if let Some(ref mutation) = common.header_mutation {
        Self::apply_header_mutations(envoy_filter, mutation, is_request);
      }
      if common.clear_route_cache
        && is_request
        && self.config.route_cache_action != RouteCacheAction::Retain
      {
        envoy_filter.clear_route_cache();
      }
    }

    if is_request {
      envoy_filter.continue_decoding();
    } else {
      envoy_filter.continue_encoding();
    }
  }

  fn handle_body_response<EHF: EnvoyHttpFilter>(
    &mut self,
    envoy_filter: &mut EHF,
    body_resp: BodyResponse,
    is_request: bool,
  ) {
    // Record body latency.
    if is_request {
      if let Some(start) = self.request_body_start_time.take() {
        let latency_us = start.elapsed().as_micros() as u64;
        let stats = self
          .logging_info
          .request_body
          .get_or_insert_with(GrpcCallBodyStats::new);
        stats.record(latency_us, 0);
      }
      self.decoding_state = CallbackState::Idle;
    } else {
      if let Some(start) = self.response_body_start_time.take() {
        let latency_us = start.elapsed().as_micros() as u64;
        let stats = self
          .logging_info
          .response_body
          .get_or_insert_with(GrpcCallBodyStats::new);
        stats.record(latency_us, 0);
      }
      self.encoding_state = CallbackState::Idle;
    }

    if let Some(common) = body_resp.response {
      if let Some(ref mutation) = common.header_mutation {
        Self::apply_header_mutations(envoy_filter, mutation, is_request);
      }
      if let Some(ref body_mut) = common.body_mutation {
        if let Some(ref new_body) = body_mut.body {
          if is_request {
            self.buffered_request_body = new_body.clone();
          } else {
            self.buffered_response_body = new_body.clone();
          }
        } else if body_mut.clear_body {
          if is_request {
            self.buffered_request_body.clear();
          } else {
            self.buffered_response_body.clear();
          }
        }
      }
    }

    if is_request {
      envoy_filter.continue_decoding();
    } else {
      envoy_filter.continue_encoding();
    }
  }

  fn handle_immediate_response<EHF: EnvoyHttpFilter>(
    &mut self,
    envoy_filter: &mut EHF,
    imm: ImmediateResponse,
  ) {
    if self.config.disable_immediate_response {
      return;
    }

    self.processing_complete = true;
    self.stats.immediate_responses_sent += 1;

    let status = if imm.status_code > 0 {
      imm.status_code
    } else {
      200
    };

    let mut header_strings: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(ref mutation) = imm.headers {
      for h in &mutation.set_headers {
        header_strings.push((h.key.clone(), h.raw_value.clone()));
      }
    }

    let headers: Vec<(&str, &[u8])> = header_strings
      .iter()
      .map(|(k, v)| (k.as_str(), v.as_slice()))
      .collect();
    let body = if imm.body.is_empty() {
      None
    } else {
      Some(imm.body.as_slice())
    };
    let details = if imm.details.is_empty() {
      None
    } else {
      Some(imm.details.as_str())
    };

    envoy_filter.send_response(status, headers, body, details);
  }

  fn handle_error<EHF: EnvoyHttpFilter>(&mut self, envoy_filter: &mut EHF, details: &str) {
    self.logging_info.error_details = Some(details.to_string());
    self.stats.streams_failed += 1;

    if self.failure_mode_allow {
      self.logging_info.failed_open = true;
      self.stats.failure_mode_allowed += 1;
      self.processing_complete = true;

      if self.in_encoding_phase {
        envoy_filter.continue_encoding();
      } else {
        envoy_filter.continue_decoding();
      }
    } else {
      self.processing_complete = true;
      envoy_filter.send_response(
        self.config.status_on_error,
        vec![("x-ext-proc-error", b"true".as_slice())],
        Some(details.as_bytes()),
        Some("ext_proc_error"),
      );
    }
  }

  fn store_logging_info<EHF: EnvoyHttpFilter>(&self, envoy_filter: &mut EHF) {
    let data = self.logging_info.serialize();
    envoy_filter.set_filter_state_bytes(b"envoy.filters.http.ext_proc", &data);
  }
}

impl<EHF: EnvoyHttpFilter> HttpFilter<EHF> for ExtProcFilter {
  fn on_request_headers(
    &mut self,
    envoy_filter: &mut EHF,
    end_of_stream: bool,
  ) -> abi::envoy_dynamic_module_type_on_http_filter_request_headers_status {
    if !self.should_send_headers(true) {
      return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue;
    }

    if self.stream_handle.is_none() && !self.open_grpc_stream(envoy_filter) {
      if self.failure_mode_allow {
        self.logging_info.failed_open = true;
        self.stats.failure_mode_allowed += 1;
        self.store_logging_info(envoy_filter);
        return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue;
      } else {
        envoy_filter.send_response(
          self.config.status_on_error,
          vec![],
          None,
          Some("ext_proc_stream_open_failed"),
        );
        return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
      }
    }

    self.request_start_time = Some(Instant::now());
    let headers = Self::collect_headers(envoy_filter, true, end_of_stream);
    let request = ProcessingRequest {
      request: ProcessingRequestType::RequestHeaders(headers),
      observability_mode: self.config.observability_mode,
    };

    if !self.send_request(envoy_filter, &request) {
      self.handle_error(envoy_filter, "Failed to send request headers");
      return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
    }

    self.decoding_state = CallbackState::HeadersCallback;

    if self.config.observability_mode {
      abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
    } else {
      abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration
    }
  }

  fn on_request_body(
    &mut self,
    envoy_filter: &mut EHF,
    end_of_stream: bool,
  ) -> abi::envoy_dynamic_module_type_on_http_filter_request_body_status {
    use abi::envoy_dynamic_module_type_on_http_filter_request_body_status as RequestBodyStatus;

    let body_mode = self.body_mode(true);
    if body_mode == BodySendMode::None || self.processing_complete {
      return RequestBodyStatus::Continue;
    }

    // If still waiting for header response, pause body processing.
    if self.decoding_state == CallbackState::HeadersCallback {
      return RequestBodyStatus::StopIterationAndBuffer;
    }

    match body_mode {
      BodySendMode::Buffered => {
        if let Some(chunks) = envoy_filter.get_buffered_request_body() {
          for chunk in chunks {
            self
              .buffered_request_body
              .extend_from_slice(chunk.as_slice());
          }
        }

        if end_of_stream {
          self.request_body_start_time = Some(Instant::now());
          let request = ProcessingRequest {
            request: ProcessingRequestType::RequestBody(HttpBody {
              body: self.buffered_request_body.clone(),
              end_of_stream: true,
            }),
            observability_mode: self.config.observability_mode,
          };
          if self.send_request(envoy_filter, &request) {
            self.decoding_state = CallbackState::BodyCallback;
            self.request_body_chunks_sent += 1;
          }
        }
        RequestBodyStatus::StopIterationAndBuffer
      },
      BodySendMode::Streamed | BodySendMode::FullDuplexStreamed => {
        // For streamed modes, send each chunk as it arrives.
        if let Some(chunks) = envoy_filter.get_buffered_request_body() {
          let mut body_data = Vec::new();
          for chunk in chunks {
            body_data.extend_from_slice(chunk.as_slice());
          }

          if !body_data.is_empty() || end_of_stream {
            if self.request_body_start_time.is_none() {
              self.request_body_start_time = Some(Instant::now());
            }
            let request = ProcessingRequest {
              request: ProcessingRequestType::RequestBody(HttpBody {
                body: body_data,
                end_of_stream,
              }),
              observability_mode: self.config.observability_mode,
            };
            if self.send_request(envoy_filter, &request) {
              self.decoding_state = CallbackState::BodyCallback;
              self.request_body_chunks_sent += 1;
            }
          }
        }

        if body_mode == BodySendMode::FullDuplexStreamed {
          // Full duplex mode continues without waiting for response.
          RequestBodyStatus::Continue
        } else {
          RequestBodyStatus::StopIterationAndBuffer
        }
      },
      BodySendMode::BufferedPartial => {
        // BufferedPartial: buffer until limit or end of stream.
        if let Some(chunks) = envoy_filter.get_buffered_request_body() {
          for chunk in chunks {
            self
              .buffered_request_body
              .extend_from_slice(chunk.as_slice());
          }
        }

        // Send when we have data and either hit end of stream or buffer is large enough.
        let should_send =
          end_of_stream || self.buffered_request_body.len() >= self.config.max_buffered_body_size();

        if should_send && !self.buffered_request_body.is_empty() {
          self.request_body_start_time = Some(Instant::now());
          let request = ProcessingRequest {
            request: ProcessingRequestType::RequestBody(HttpBody {
              body: self.buffered_request_body.clone(),
              end_of_stream,
            }),
            observability_mode: self.config.observability_mode,
          };
          if self.send_request(envoy_filter, &request) {
            self.decoding_state = CallbackState::BodyCallback;
            self.request_body_chunks_sent += 1;
          }
          self.buffered_request_body.clear();
        }
        RequestBodyStatus::StopIterationAndBuffer
      },
      BodySendMode::None => RequestBodyStatus::Continue,
    }
  }

  fn on_request_trailers(
    &mut self,
    _envoy_filter: &mut EHF,
  ) -> abi::envoy_dynamic_module_type_on_http_filter_request_trailers_status {
    abi::envoy_dynamic_module_type_on_http_filter_request_trailers_status::Continue
  }

  fn on_response_headers(
    &mut self,
    envoy_filter: &mut EHF,
    end_of_stream: bool,
  ) -> abi::envoy_dynamic_module_type_on_http_filter_response_headers_status {
    self.in_encoding_phase = true;

    if !self.should_send_headers(false) {
      return abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue;
    }

    if self.stream_handle.is_none() {
      if self.failure_mode_allow {
        return abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue;
      } else {
        envoy_filter.send_response(
          self.config.status_on_error,
          vec![],
          None,
          Some("ext_proc_no_stream"),
        );
        return abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::StopIteration;
      }
    }

    self.response_start_time = Some(Instant::now());
    let headers = Self::collect_headers(envoy_filter, false, end_of_stream);
    let request = ProcessingRequest {
      request: ProcessingRequestType::ResponseHeaders(headers),
      observability_mode: self.config.observability_mode,
    };

    if !self.send_request(envoy_filter, &request) {
      self.handle_error(envoy_filter, "Failed to send response headers");
      return abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::StopIteration;
    }

    self.encoding_state = CallbackState::HeadersCallback;

    if self.config.observability_mode {
      abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue
    } else {
      abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::StopIteration
    }
  }

  fn on_response_body(
    &mut self,
    envoy_filter: &mut EHF,
    end_of_stream: bool,
  ) -> abi::envoy_dynamic_module_type_on_http_filter_response_body_status {
    use abi::envoy_dynamic_module_type_on_http_filter_response_body_status as ResponseBodyStatus;

    let body_mode = self.body_mode(false);
    if body_mode == BodySendMode::None || self.processing_complete {
      return ResponseBodyStatus::Continue;
    }

    // If still waiting for header response, pause body processing.
    if self.encoding_state == CallbackState::HeadersCallback {
      return ResponseBodyStatus::StopIterationAndBuffer;
    }

    match body_mode {
      BodySendMode::Buffered => {
        if let Some(chunks) = envoy_filter.get_buffered_response_body() {
          for chunk in chunks {
            self
              .buffered_response_body
              .extend_from_slice(chunk.as_slice());
          }
        }

        if end_of_stream {
          self.response_body_start_time = Some(Instant::now());
          let request = ProcessingRequest {
            request: ProcessingRequestType::ResponseBody(HttpBody {
              body: self.buffered_response_body.clone(),
              end_of_stream: true,
            }),
            observability_mode: self.config.observability_mode,
          };
          if self.send_request(envoy_filter, &request) {
            self.encoding_state = CallbackState::BodyCallback;
            self.response_body_chunks_sent += 1;
          }
        }
        ResponseBodyStatus::StopIterationAndBuffer
      },
      BodySendMode::Streamed | BodySendMode::FullDuplexStreamed => {
        // For streamed modes, send each chunk as it arrives.
        if let Some(chunks) = envoy_filter.get_buffered_response_body() {
          let mut body_data = Vec::new();
          for chunk in chunks {
            body_data.extend_from_slice(chunk.as_slice());
          }

          if !body_data.is_empty() || end_of_stream {
            if self.response_body_start_time.is_none() {
              self.response_body_start_time = Some(Instant::now());
            }
            let request = ProcessingRequest {
              request: ProcessingRequestType::ResponseBody(HttpBody {
                body: body_data,
                end_of_stream,
              }),
              observability_mode: self.config.observability_mode,
            };
            if self.send_request(envoy_filter, &request) {
              self.encoding_state = CallbackState::BodyCallback;
              self.response_body_chunks_sent += 1;
            }
          }
        }

        if body_mode == BodySendMode::FullDuplexStreamed {
          // Full duplex mode continues without waiting for response.
          ResponseBodyStatus::Continue
        } else {
          ResponseBodyStatus::StopIterationAndBuffer
        }
      },
      BodySendMode::BufferedPartial => {
        // BufferedPartial: buffer until limit or end of stream.
        if let Some(chunks) = envoy_filter.get_buffered_response_body() {
          for chunk in chunks {
            self
              .buffered_response_body
              .extend_from_slice(chunk.as_slice());
          }
        }

        // Send when we have data and either hit end of stream or buffer is large enough.
        let should_send = end_of_stream
          || self.buffered_response_body.len() >= self.config.max_buffered_body_size();

        if should_send && !self.buffered_response_body.is_empty() {
          self.response_body_start_time = Some(Instant::now());
          let request = ProcessingRequest {
            request: ProcessingRequestType::ResponseBody(HttpBody {
              body: self.buffered_response_body.clone(),
              end_of_stream,
            }),
            observability_mode: self.config.observability_mode,
          };
          if self.send_request(envoy_filter, &request) {
            self.encoding_state = CallbackState::BodyCallback;
            self.response_body_chunks_sent += 1;
          }
          self.buffered_response_body.clear();
        }
        ResponseBodyStatus::StopIterationAndBuffer
      },
      BodySendMode::None => ResponseBodyStatus::Continue,
    }
  }

  fn on_response_trailers(
    &mut self,
    _envoy_filter: &mut EHF,
  ) -> abi::envoy_dynamic_module_type_on_http_filter_response_trailers_status {
    abi::envoy_dynamic_module_type_on_http_filter_response_trailers_status::Continue
  }

  fn on_http_stream_data(
    &mut self,
    envoy_filter: &mut EHF,
    stream_handle: u64,
    data: &[EnvoyBuffer],
    _end_stream: bool,
  ) {
    if Some(stream_handle) != self.stream_handle {
      return;
    }

    for chunk in data {
      self.response_buffer.extend_from_slice(chunk.as_slice());
      self.logging_info.bytes_received += chunk.as_slice().len() as u64;
    }

    while self.response_buffer.len() >= GRPC_HEADER_SIZE {
      let len = u32::from_be_bytes([
        self.response_buffer[1],
        self.response_buffer[2],
        self.response_buffer[3],
        self.response_buffer[4],
      ]) as usize;

      if self.response_buffer.len() < GRPC_HEADER_SIZE + len {
        break;
      }

      if let Some((_, payload)) = decode_grpc_frame(&self.response_buffer) {
        if let Some(response) = ProcessingResponse::decode(payload) {
          self.handle_processing_response(envoy_filter, response);
        }
      }

      self.response_buffer.drain(.. GRPC_HEADER_SIZE + len);
    }
  }

  fn on_http_stream_trailers(
    &mut self,
    envoy_filter: &mut EHF,
    stream_handle: u64,
    trailers: &[(EnvoyBuffer, EnvoyBuffer)],
  ) {
    if Some(stream_handle) != self.stream_handle {
      return;
    }

    for (key, value) in trailers {
      let key_str = String::from_utf8_lossy(key.as_slice());
      if key_str == "grpc-status" {
        let status_str = String::from_utf8_lossy(value.as_slice());
        if let Ok(status) = status_str.parse::<u32>() {
          if status != 0 {
            let details = format!("gRPC status: {}", status);
            self.handle_error(envoy_filter, &details);
            return;
          }
        }
      }
    }
  }

  fn on_http_stream_complete(&mut self, envoy_filter: &mut EHF, stream_handle: u64) {
    if Some(stream_handle) != self.stream_handle {
      return;
    }
    self.stream_handle = None;
    self.stats.streams_closed += 1;
    self.store_logging_info(envoy_filter);
  }

  fn on_http_stream_reset(
    &mut self,
    envoy_filter: &mut EHF,
    stream_handle: u64,
    _reset_reason: abi::envoy_dynamic_module_type_http_stream_reset_reason,
  ) {
    if Some(stream_handle) != self.stream_handle {
      return;
    }
    self.handle_error(envoy_filter, "Stream reset");
    self.stream_handle = None;
    self.store_logging_info(envoy_filter);
  }

  fn on_stream_complete(&mut self, envoy_filter: &mut EHF) {
    if let Some(handle) = self.stream_handle.take() {
      unsafe {
        envoy_filter.reset_http_stream(handle);
      }
    }
    self.store_logging_info(envoy_filter);
  }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_encode_varint() {
    let mut buf = Vec::new();
    encode_varint(1, &mut buf);
    assert_eq!(buf, vec![1]);

    buf.clear();
    encode_varint(300, &mut buf);
    assert_eq!(buf, vec![0xAC, 0x02]);
  }

  #[test]
  fn test_decode_varint() {
    let (val, consumed) = decode_varint(&[1]).unwrap();
    assert_eq!(val, 1);
    assert_eq!(consumed, 1);

    let (val, consumed) = decode_varint(&[0xAC, 0x02]).unwrap();
    assert_eq!(val, 300);
    assert_eq!(consumed, 2);
  }

  #[test]
  fn test_grpc_framing() {
    let message = b"test message";
    let framed = encode_grpc_message(message);
    assert_eq!(framed.len(), GRPC_HEADER_SIZE + message.len());
    assert_eq!(framed[0], 0); // No compression.

    let (compressed, payload) = decode_grpc_frame(&framed).unwrap();
    assert!(!compressed);
    assert_eq!(payload, message);
  }

  #[test]
  fn test_header_value_encode() {
    let h = HeaderValue {
      key: "content-type".to_string(),
      raw_value: b"application/json".to_vec(),
    };
    let encoded = h.encode();
    assert!(!encoded.is_empty());
  }

  #[test]
  fn test_http_headers_encode() {
    let headers = HttpHeaders {
      headers: vec![HeaderValue {
        key: ":method".to_string(),
        raw_value: b"GET".to_vec(),
      }],
      end_of_stream: true,
    };
    let encoded = headers.encode();
    assert!(!encoded.is_empty());
  }

  #[test]
  fn test_processing_request_encode() {
    let request = ProcessingRequest {
      request: ProcessingRequestType::RequestHeaders(HttpHeaders {
        headers: vec![],
        end_of_stream: false,
      }),
      observability_mode: true,
    };
    let encoded = request.encode();
    assert!(!encoded.is_empty());
  }

  #[test]
  fn test_config_default() {
    let config = ExtProcConfig::default();
    assert!(config.cluster_name.is_empty());
    assert_eq!(config.message_timeout_ms, 10000);
    assert!(!config.failure_mode_allow);
  }

  #[test]
  fn test_logging_info_serialize() {
    let mut info = ExtProcLoggingInfo::default();
    info.request_headers = Some(GrpcCallStats {
      latency_us: 1000,
      call_status: 0,
    });
    info.failed_open = true;
    info.bytes_sent = 100;

    let serialized = info.serialize();
    let as_str = String::from_utf8(serialized).unwrap();

    assert!(as_str.contains("request_headers_latency_us=1000"));
    assert!(as_str.contains("failed_open=true"));
    assert!(as_str.contains("bytes_sent=100"));
  }

  #[test]
  fn test_stats_default() {
    let stats = ExtProcStats::default();
    assert_eq!(stats.streams_started, 0);
    assert_eq!(stats.stream_msgs_sent, 0);
  }

  #[test]
  fn test_callback_state_default() {
    assert_eq!(CallbackState::default(), CallbackState::Idle);
  }
}
