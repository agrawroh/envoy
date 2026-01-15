//! Integration tests for the ExtProc Dynamic Module implementation.
//!
//! These tests verify the complete functionality of the ExtProc filter, including:
//! - Protobuf encoding/decoding utilities
//! - gRPC framing
//! - ProcessingRequest/ProcessingResponse message handling
//! - Configuration and statistics
//! - Logging info serialization

#[path = "ext_proc.rs"]
#[allow(dead_code)]
mod ext_proc;

#[allow(unused_imports)]
use ext_proc::{
  decode_grpc_frame,
  decode_varint,
  encode_grpc_message,
  encode_varint,
  BodySendMode,
  CallbackState,
  CommonResponse,
  ExtProcConfig,
  ExtProcLoggingInfo,
  ExtProcStats,
  GrpcCallBodyStats,
  GrpcCallStats,
  HeaderMutation,
  HeaderSendMode,
  HeaderValue,
  HttpBody,
  HttpHeaders,
  ProcessingMode,
  ProcessingRequest,
  ProcessingRequestType,
  ProcessingResponse,
  ProcessingResponseType,
  ResponseStatus,
  RouteCacheAction,
  StreamedImmediateResponse,
  GRPC_HEADER_SIZE,
};

// ============================================================================
// Varint Encoding/Decoding Tests
// ============================================================================

#[test]
fn test_varint_roundtrip_small() {
  for val in [0u64, 1, 127] {
    let mut buf = Vec::new();
    ext_proc::encode_varint(val, &mut buf);
    let (decoded, consumed) = ext_proc::decode_varint(&buf).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, buf.len());
  }
}

#[test]
fn test_varint_roundtrip_medium() {
  for val in [128u64, 255, 300, 16383] {
    let mut buf = Vec::new();
    ext_proc::encode_varint(val, &mut buf);
    let (decoded, consumed) = ext_proc::decode_varint(&buf).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, buf.len());
  }
}

#[test]
fn test_varint_roundtrip_large() {
  for val in [16384u64, 2097151, 268435455, u64::MAX] {
    let mut buf = Vec::new();
    ext_proc::encode_varint(val, &mut buf);
    let (decoded, consumed) = ext_proc::decode_varint(&buf).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, buf.len());
  }
}

#[test]
fn test_decode_varint_incomplete() {
  // Incomplete varint (high bit set but no continuation).
  assert!(ext_proc::decode_varint(&[0x80]).is_none());
}

// ============================================================================
// gRPC Framing Tests
// ============================================================================

#[test]
fn test_grpc_frame_empty_message() {
  let message = b"";
  let framed = encode_grpc_message(message);
  assert_eq!(framed.len(), GRPC_HEADER_SIZE);
  assert_eq!(framed[0], 0); // No compression.
  assert_eq!(&framed[1 .. 5], &[0, 0, 0, 0]); // Length 0.
}

#[test]
fn test_grpc_frame_small_message() {
  let message = b"hello";
  let framed = encode_grpc_message(message);
  assert_eq!(framed.len(), GRPC_HEADER_SIZE + 5);
  assert_eq!(framed[0], 0);
  assert_eq!(&framed[1 .. 5], &[0, 0, 0, 5]); // Length 5.

  let (compressed, payload) = decode_grpc_frame(&framed).unwrap();
  assert!(!compressed);
  assert_eq!(payload, b"hello");
}

#[test]
fn test_grpc_frame_large_message() {
  let message = vec![0xAB; 1000];
  let framed = encode_grpc_message(&message);
  assert_eq!(framed.len(), GRPC_HEADER_SIZE + 1000);

  let (compressed, payload) = decode_grpc_frame(&framed).unwrap();
  assert!(!compressed);
  assert_eq!(payload.len(), 1000);
}

#[test]
fn test_decode_grpc_frame_incomplete_header() {
  assert!(decode_grpc_frame(&[]).is_none());
  assert!(decode_grpc_frame(&[0, 0]).is_none());
  assert!(decode_grpc_frame(&[0, 0, 0, 0]).is_none());
}

#[test]
fn test_decode_grpc_frame_incomplete_payload() {
  // Header says 10 bytes but only 5 available.
  let data = [0, 0, 0, 0, 10, 1, 2, 3, 4, 5];
  assert!(decode_grpc_frame(&data).is_none());
}

// ============================================================================
// Header Value Tests
// ============================================================================

#[test]
fn test_header_value_encoding() {
  let header = HeaderValue {
    key: "x-custom-header".to_string(),
    raw_value: b"custom-value".to_vec(),
  };
  let encoded = header.encode();
  assert!(!encoded.is_empty());
  // Verify field 1 (key) and field 3 (raw_value) are present.
  assert!(encoded.len() > header.key.len() + header.raw_value.len());
}

#[test]
fn test_header_value_empty() {
  let header = HeaderValue {
    key: String::new(),
    raw_value: Vec::new(),
  };
  let encoded = header.encode();
  assert!(encoded.is_empty()); // Empty fields should not produce output.
}

// ============================================================================
// HTTP Headers Tests
// ============================================================================

#[test]
fn test_http_headers_encoding() {
  let headers = HttpHeaders {
    headers: vec![
      HeaderValue {
        key: ":method".to_string(),
        raw_value: b"POST".to_vec(),
      },
      HeaderValue {
        key: ":path".to_string(),
        raw_value: b"/api/v1/process".to_vec(),
      },
      HeaderValue {
        key: "content-type".to_string(),
        raw_value: b"application/json".to_vec(),
      },
    ],
    end_of_stream: false,
  };
  let encoded = headers.encode();
  assert!(!encoded.is_empty());
}

#[test]
fn test_http_headers_end_of_stream() {
  let headers = HttpHeaders {
    headers: vec![],
    end_of_stream: true,
  };
  let encoded = headers.encode();
  // Should contain the end_of_stream bool field.
  assert!(!encoded.is_empty());
}

// ============================================================================
// HTTP Body Tests
// ============================================================================

#[test]
fn test_http_body_encoding() {
  let body = HttpBody {
    body: b"{\"key\": \"value\"}".to_vec(),
    end_of_stream: true,
  };
  let encoded = body.encode();
  assert!(!encoded.is_empty());
}

#[test]
fn test_http_body_empty() {
  let body = HttpBody {
    body: Vec::new(),
    end_of_stream: false,
  };
  let encoded = body.encode();
  assert!(encoded.is_empty()); // Empty body and false end_of_stream.
}

// ============================================================================
// ProcessingRequest Tests
// ============================================================================

#[test]
fn test_processing_request_headers() {
  let request = ProcessingRequest {
    request: ProcessingRequestType::RequestHeaders(HttpHeaders {
      headers: vec![HeaderValue {
        key: ":method".to_string(),
        raw_value: b"GET".to_vec(),
      }],
      end_of_stream: false,
    }),
    observability_mode: false,
  };
  let encoded = request.encode();
  assert!(!encoded.is_empty());
}

#[test]
fn test_processing_request_body() {
  let request = ProcessingRequest {
    request: ProcessingRequestType::RequestBody(HttpBody {
      body: b"request body".to_vec(),
      end_of_stream: true,
    }),
    observability_mode: true,
  };
  let encoded = request.encode();
  assert!(!encoded.is_empty());
}

#[test]
fn test_processing_request_response_headers() {
  let request = ProcessingRequest {
    request: ProcessingRequestType::ResponseHeaders(HttpHeaders {
      headers: vec![HeaderValue {
        key: ":status".to_string(),
        raw_value: b"200".to_vec(),
      }],
      end_of_stream: false,
    }),
    observability_mode: false,
  };
  let encoded = request.encode();
  assert!(!encoded.is_empty());
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_config_default_values() {
  let config = ExtProcConfig::default();
  assert!(config.cluster_name.is_empty());
  assert_eq!(config.message_timeout_ms, 10000);
  assert!(config.allow_mode_override);
  assert!(!config.failure_mode_allow);
  assert_eq!(config.status_on_error, 500);
  assert!(!config.disable_immediate_response);
  assert_eq!(config.route_cache_action, RouteCacheAction::Default);
  assert!(!config.observability_mode);
}

#[test]
fn test_config_custom_values() {
  let config = ExtProcConfig {
    cluster_name: "ext-proc-cluster".to_string(),
    processing_mode: ProcessingMode {
      request_header_mode: HeaderSendMode::Send,
      response_header_mode: HeaderSendMode::Skip,
      request_body_mode: BodySendMode::Buffered,
      response_body_mode: BodySendMode::Streamed,
    },
    message_timeout_ms: 5000,
    max_message_timeout_ms: 30000,
    allow_mode_override: false,
    failure_mode_allow: true,
    status_on_error: 503,
    disable_immediate_response: true,
    route_cache_action: RouteCacheAction::Clear,
    observability_mode: true,
    max_buffered_body_bytes: 2 * 1024 * 1024,
  };

  assert_eq!(config.cluster_name, "ext-proc-cluster");
  assert_eq!(config.message_timeout_ms, 5000);
  assert!(!config.allow_mode_override);
  assert!(config.failure_mode_allow);
  assert_eq!(config.status_on_error, 503);
  assert!(config.disable_immediate_response);
  assert_eq!(config.route_cache_action, RouteCacheAction::Clear);
  assert!(config.observability_mode);
}

#[test]
fn test_processing_mode_default() {
  let mode = ProcessingMode::default();
  assert_eq!(mode.request_header_mode, HeaderSendMode::Default);
  assert_eq!(mode.response_header_mode, HeaderSendMode::Default);
  assert_eq!(mode.request_body_mode, BodySendMode::None);
  assert_eq!(mode.response_body_mode, BodySendMode::None);
}

// ============================================================================
// Header/Body Mode Tests
// ============================================================================

#[test]
fn test_header_send_mode_values() {
  assert_eq!(HeaderSendMode::Default as i32, 0);
  assert_eq!(HeaderSendMode::Send as i32, 1);
  assert_eq!(HeaderSendMode::Skip as i32, 2);
}

#[test]
fn test_body_send_mode_values() {
  assert_eq!(BodySendMode::None as i32, 0);
  assert_eq!(BodySendMode::Streamed as i32, 1);
  assert_eq!(BodySendMode::Buffered as i32, 2);
  assert_eq!(BodySendMode::BufferedPartial as i32, 3);
  assert_eq!(BodySendMode::FullDuplexStreamed as i32, 4);
}

#[test]
fn test_route_cache_action_values() {
  assert_eq!(RouteCacheAction::Default as i32, 0);
  assert_eq!(RouteCacheAction::Clear as i32, 1);
  assert_eq!(RouteCacheAction::Retain as i32, 2);
}

// ============================================================================
// Statistics Tests
// ============================================================================

#[test]
fn test_stats_default() {
  let stats = ExtProcStats::default();
  assert_eq!(stats.streams_started, 0);
  assert_eq!(stats.stream_msgs_sent, 0);
  assert_eq!(stats.stream_msgs_received, 0);
  assert_eq!(stats.streams_failed, 0);
  assert_eq!(stats.failure_mode_allowed, 0);
  assert_eq!(stats.immediate_responses_sent, 0);
}

#[test]
fn test_stats_increment() {
  let mut stats = ExtProcStats::default();
  stats.streams_started += 1;
  stats.stream_msgs_sent += 5;
  stats.stream_msgs_received += 5;

  assert_eq!(stats.streams_started, 1);
  assert_eq!(stats.stream_msgs_sent, 5);
  assert_eq!(stats.stream_msgs_received, 5);
}

// ============================================================================
// Logging Info Tests
// ============================================================================

#[test]
fn test_logging_info_default() {
  let info = ExtProcLoggingInfo::default();
  assert!(info.request_headers.is_none());
  assert!(info.response_headers.is_none());
  assert!(!info.failed_open);
  assert!(info.error_details.is_none());
  assert_eq!(info.bytes_sent, 0);
  assert_eq!(info.bytes_received, 0);
}

#[test]
fn test_logging_info_serialize_request() {
  let info = ExtProcLoggingInfo {
    request_headers: Some(GrpcCallStats {
      latency_us: 500,
      call_status: 0,
    }),
    ..Default::default()
  };

  let serialized = info.serialize();
  let as_str = String::from_utf8(serialized).unwrap();

  assert!(as_str.contains("request_headers_latency_us=500"));
  assert!(!as_str.contains("failed_open"));
}

#[test]
fn test_logging_info_serialize_response() {
  let info = ExtProcLoggingInfo {
    response_headers: Some(GrpcCallStats {
      latency_us: 750,
      call_status: 0,
    }),
    ..Default::default()
  };

  let serialized = info.serialize();
  let as_str = String::from_utf8(serialized).unwrap();

  assert!(as_str.contains("response_headers_latency_us=750"));
}

#[test]
fn test_logging_info_serialize_failed_open() {
  let info = ExtProcLoggingInfo {
    failed_open: true,
    error_details: Some("connection refused".to_string()),
    ..Default::default()
  };

  let serialized = info.serialize();
  let as_str = String::from_utf8(serialized).unwrap();

  assert!(as_str.contains("failed_open=true"));
  assert!(as_str.contains("error_details=connection refused"));
}

#[test]
fn test_logging_info_serialize_bytes() {
  let info = ExtProcLoggingInfo {
    bytes_sent: 1024,
    bytes_received: 2048,
    ..Default::default()
  };

  let serialized = info.serialize();
  let as_str = String::from_utf8(serialized).unwrap();

  assert!(as_str.contains("bytes_sent=1024"));
  assert!(as_str.contains("bytes_received=2048"));
}

#[test]
fn test_logging_info_serialize_full() {
  let info = ExtProcLoggingInfo {
    request_headers: Some(GrpcCallStats {
      latency_us: 100,
      call_status: 0,
    }),
    response_headers: Some(GrpcCallStats {
      latency_us: 200,
      call_status: 0,
    }),
    request_body: None,
    response_body: None,
    failed_open: true,
    error_details: Some("test error".to_string()),
    bytes_sent: 500,
    bytes_received: 1000,
  };

  let serialized = info.serialize();
  let as_str = String::from_utf8(serialized).unwrap();

  assert!(as_str.contains("request_headers_latency_us=100"));
  assert!(as_str.contains("response_headers_latency_us=200"));
  assert!(as_str.contains("failed_open=true"));
  assert!(as_str.contains("error_details=test error"));
  assert!(as_str.contains("bytes_sent=500"));
  assert!(as_str.contains("bytes_received=1000"));
}

// ============================================================================
// Callback State Tests
// ============================================================================

#[test]
fn test_callback_state_default() {
  assert_eq!(CallbackState::default(), CallbackState::Idle);
}

#[test]
fn test_callback_state_variants() {
  let state = CallbackState::HeadersCallback;
  assert!(matches!(state, CallbackState::HeadersCallback));

  let state = CallbackState::BodyCallback;
  assert!(matches!(state, CallbackState::BodyCallback));
}

// ============================================================================
// Response Status Tests
// ============================================================================

#[test]
fn test_response_status_values() {
  assert_eq!(ResponseStatus::Continue as i32, 0);
  assert_eq!(ResponseStatus::ContinueAndReplace as i32, 1);
}

// ============================================================================
// GrpcCallStats Tests
// ============================================================================

#[test]
fn test_grpc_call_stats_default() {
  let stats = GrpcCallStats::default();
  assert_eq!(stats.latency_us, 0);
  assert_eq!(stats.call_status, 0);
}

#[test]
fn test_grpc_call_stats_custom() {
  let stats = GrpcCallStats {
    latency_us: 5000,
    call_status: 14, // gRPC UNAVAILABLE status code.
  };
  assert_eq!(stats.latency_us, 5000);
  assert_eq!(stats.call_status, 14);
}

// ============================================================================
// ProcessingResponse Decoding Tests
// ============================================================================

#[test]
fn test_processing_response_decode_empty() {
  let data = [];
  let resp = ProcessingResponse::decode(&data);
  assert!(resp.is_some());
  let resp = resp.unwrap();
  assert!(resp.response.is_none());
  assert!(resp.mode_override.is_none());
}

#[test]
fn test_common_response_default() {
  let resp = CommonResponse::default();
  assert_eq!(resp.status, ResponseStatus::Continue);
  assert!(resp.header_mutation.is_none());
  assert!(resp.body_mutation.is_none());
  assert!(!resp.clear_route_cache);
}

#[test]
fn test_header_mutation_default() {
  let mutation = HeaderMutation::default();
  assert!(mutation.set_headers.is_empty());
  assert!(mutation.remove_headers.is_empty());
}

// ============================================================================
// ExtProcConfig Extended Tests
// ============================================================================

#[test]
fn test_config_max_buffered_body_size() {
  let config = ExtProcConfig::default();
  // Default is 1MB.
  assert_eq!(config.max_buffered_body_size(), 1024 * 1024);
}

#[test]
fn test_config_custom_buffer_size() {
  let config = ExtProcConfig {
    max_buffered_body_bytes: 512 * 1024,
    ..Default::default()
  };
  assert_eq!(config.max_buffered_body_size(), 512 * 1024);
}

// ============================================================================
// ExtProcStats Extended Tests
// ============================================================================

#[test]
fn test_stats_all_fields() {
  let mut stats = ExtProcStats::default();
  stats.streams_started = 10;
  stats.stream_msgs_sent = 20;
  stats.stream_msgs_received = 18;
  stats.spurious_msgs_received = 1;
  stats.streams_closed = 8;
  stats.streams_failed = 2;
  stats.failure_mode_allowed = 1;
  stats.message_timeouts = 1;
  stats.rejected_header_mutations = 0;
  stats.override_message_timeout_received = 2;
  stats.override_message_timeout_ignored = 1;
  stats.clear_route_cache_ignored = 0;
  stats.immediate_responses_sent = 3;

  assert_eq!(stats.streams_started, 10);
  assert_eq!(stats.streams_closed, 8);
  assert_eq!(stats.streams_failed, 2);
  assert_eq!(stats.message_timeouts, 1);
  assert_eq!(stats.immediate_responses_sent, 3);
  assert_eq!(stats.spurious_msgs_received, 1);
  assert_eq!(stats.override_message_timeout_received, 2);
  assert_eq!(stats.override_message_timeout_ignored, 1);
}

// ============================================================================
// StreamedImmediateResponse Tests
// ============================================================================

#[test]
fn test_streamed_immediate_response_default() {
  let resp = StreamedImmediateResponse::default();
  assert!(resp.status_code.is_none());
  assert!(resp.headers.is_none());
  assert!(resp.body_chunk.is_empty());
  assert!(!resp.end_of_stream);
  assert!(resp.grpc_status.is_none());
  assert!(resp.details.is_empty());
}

#[test]
fn test_streamed_immediate_response_with_values() {
  let resp = StreamedImmediateResponse {
    status_code: Some(200),
    headers: None,
    body_chunk: b"chunk data".to_vec(),
    end_of_stream: true,
    grpc_status: Some(0),
    details: "completed".to_string(),
  };
  assert_eq!(resp.status_code, Some(200));
  assert_eq!(resp.body_chunk, b"chunk data".to_vec());
  assert!(resp.end_of_stream);
  assert_eq!(resp.grpc_status, Some(0));
  assert_eq!(resp.details, "completed");
}

// ============================================================================
// GrpcCallBodyStats Tests
// ============================================================================

#[test]
fn test_grpc_call_body_stats_new() {
  let stats = GrpcCallBodyStats::new();
  assert_eq!(stats.call_count, 0);
  assert_eq!(stats.last_call_status, 0);
  assert_eq!(stats.total_latency_us, 0);
  assert_eq!(stats.max_latency_us, 0);
  assert_eq!(stats.min_latency_us, u64::MAX);
}

#[test]
fn test_grpc_call_body_stats_record() {
  let mut stats = GrpcCallBodyStats::new();
  stats.record(100, 0);
  assert_eq!(stats.call_count, 1);
  assert_eq!(stats.total_latency_us, 100);
  assert_eq!(stats.max_latency_us, 100);
  assert_eq!(stats.min_latency_us, 100);

  stats.record(200, 0);
  assert_eq!(stats.call_count, 2);
  assert_eq!(stats.total_latency_us, 300);
  assert_eq!(stats.max_latency_us, 200);
  assert_eq!(stats.min_latency_us, 100);

  stats.record(50, 1);
  assert_eq!(stats.call_count, 3);
  assert_eq!(stats.total_latency_us, 350);
  assert_eq!(stats.max_latency_us, 200);
  assert_eq!(stats.min_latency_us, 50);
  assert_eq!(stats.last_call_status, 1);
}

// ============================================================================
// ExtProcLoggingInfo Body Stats Tests
// ============================================================================

#[test]
fn test_logging_info_serialize_body_stats() {
  let info = ExtProcLoggingInfo {
    request_body: Some(GrpcCallBodyStats {
      call_count: 5,
      last_call_status: 0,
      total_latency_us: 5000,
      max_latency_us: 1500,
      min_latency_us: 800,
    }),
    response_body: Some(GrpcCallBodyStats {
      call_count: 3,
      last_call_status: 0,
      total_latency_us: 3000,
      max_latency_us: 1200,
      min_latency_us: 900,
    }),
    ..Default::default()
  };

  let serialized = info.serialize();
  let as_str = String::from_utf8(serialized).unwrap();

  assert!(as_str.contains("request_body_call_count=5"));
  assert!(as_str.contains("request_body_total_latency_us=5000"));
  assert!(as_str.contains("response_body_call_count=3"));
  assert!(as_str.contains("response_body_total_latency_us=3000"));
}

// ============================================================================
// ProcessingResponse Override Message Timeout Tests
// ============================================================================

#[test]
fn test_processing_response_fields() {
  let resp = ProcessingResponse::decode(&[]).unwrap();
  assert!(resp.response.is_none());
  assert!(resp.mode_override.is_none());
  assert!(resp.override_message_timeout_ms.is_none());
}

// ============================================================================
// ProcessingResponseType Tests
// ============================================================================

#[test]
fn test_processing_response_type_variants() {
  use ext_proc::{BodyResponse, HeadersResponse, ImmediateResponse};

  let headers_resp = ProcessingResponseType::RequestHeaders(HeadersResponse::default());
  assert!(matches!(
    headers_resp,
    ProcessingResponseType::RequestHeaders(_)
  ));

  let body_resp = ProcessingResponseType::RequestBody(BodyResponse::default());
  assert!(matches!(body_resp, ProcessingResponseType::RequestBody(_)));

  let imm_resp = ProcessingResponseType::ImmediateResponse(ImmediateResponse::default());
  assert!(matches!(
    imm_resp,
    ProcessingResponseType::ImmediateResponse(_)
  ));

  let streamed_resp =
    ProcessingResponseType::StreamedImmediateResponse(StreamedImmediateResponse::default());
  assert!(matches!(
    streamed_resp,
    ProcessingResponseType::StreamedImmediateResponse(_)
  ));
}
