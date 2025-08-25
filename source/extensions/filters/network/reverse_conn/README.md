# Reverse Connection Generic Proxy Filter (Terminal Filter)

This filter provides a robust, **protocol-agnostic** implementation for handling reverse connection acceptance/rejection using the **Generic Proxy StreamFilter interface**. It's designed as a **terminal filter** that stops processing after handling reverse connection requests.

## What It Does

The filter **only** handles:
1. **Reverse Connection Acceptance/Rejection** - Processes POST requests to `/reverse_connections/request`
2. **Protobuf Parsing** - Extracts node, cluster, and tenant UUIDs from the request body
3. **SSL Certificate Processing** - Overrides UUIDs with values from SSL certificate DNS SANs
4. **Socket Management** - Duplicates and saves the connection to the upstream socket manager
5. **Terminal Behavior** - Closes the connection after processing (no further filters run)

## How It Works

### **1. Generic Proxy StreamFilter Interface**
```cpp
class ReverseConnFilter : public Network::Filter, 
                         public GenericProxy::StreamFilter,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  // Terminal filter behavior
  bool isTerminalFilter() const { return true; }
  
  // GenericProxy::DecoderFilter
  GenericProxy::HeaderFilterStatus decodeHeaderFrame(GenericProxy::RequestHeaderFrame& request) override;
  GenericProxy::CommonFilterStatus decodeCommonFrame(GenericProxy::RequestCommonFrame& request) override;
};
```

### **2. Protocol-Agnostic Request Processing**
```cpp
GenericProxy::HeaderFilterStatus ReverseConnFilter::decodeHeaderFrame(GenericProxy::RequestHeaderFrame& request) {
  // Check if this is a reverse connection request
  if (isReverseConnectionRequest(request)) {
    ENVOY_LOG(debug, "ReverseConnFilter: Detected reverse connection request");
    is_reverse_connection_request_ = true;
    
    // Continue to receive body frames
    return GenericProxy::HeaderFilterStatus::Continue;
  }

  // Not a reverse connection request, continue to next filter
  return GenericProxy::HeaderFilterStatus::Continue;
}
```

### **3. Terminal Filter Behavior**
```cpp
GenericProxy::CommonFilterStatus ReverseConnFilter::decodeCommonFrame(GenericProxy::RequestCommonFrame& request) {
  if (!is_reverse_connection_request_) {
    return GenericProxy::CommonFilterStatus::Continue;
  }

  // Extract body data from the common frame
  extractRequestBody(request);
  
  // Process when complete
  if (!request_body_.empty()) {
    processReverseConnectionRequest();
    
    // As a terminal filter, stop processing after handling the request
    return GenericProxy::CommonFilterStatus::StopIteration;
  }

  return GenericProxy::CommonFilterStatus::Continue;
}
```

### **4. Connection Closure**
```cpp
void ReverseConnFilter::closeConnection() {
  // Mark connection as reused
  connection->setSocketReused(true);
  
  // Reset file events on the connection socket
  if (connection->getSocket()) {
    connection->getSocket()->ioHandle().resetFileEvents();
  }
  
  // Close the connection
  connection->close(Network::ConnectionCloseType::NoFlush, "accepted_reverse_conn");
}
```

## Configuration

### **Correct Configuration Structure**

Your filter must be configured as part of a **Generic Proxy filter chain**, not as a standalone network filter:

```yaml
static_resources:
  listeners:
  - name: "reverse_conn_listener"
    address:
      socket_address:
        address: "0.0.0.0"
        port_value: 8080
    listener_filters:
      # Generic Proxy network filter intercepts all TCP data
      - name: "envoy.filters.network.generic_proxy"
        typed_config:
          "@type": "type.googleapis.com/envoy.extensions.filters.network.generic_proxy.v3.GenericProxy"
          stat_prefix: "reverse_conn"
          codec_config:
            # HTTP/1.1 codec parses raw HTTP data into frames
            name: "envoy.generic_proxy.codecs.http1"
            typed_config:
              "@type": "type.googleapis.com/envoy.extensions/filters.network/generic_proxy.codecs/http1/v3.Http1CodecConfig"
          filters:
            # Your reverse connection filter (L7 filter, not network filter)
            - name: "envoy.filters.generic.reverse_conn"
              typed_config:
                "@type": "type.googleapis.com/envoy/extensions/filters/generic/reverse_conn/v3.ReverseConn"
            
            # Router filter for non-reverse-connection requests
            - name: "envoy.filters.generic.router"
              typed_config:
                "@type": "type.googleapis.com/envoy/extensions/filters/network/generic_proxy/router/v3.Router"
                bind_upstream_connection: false
```

### **Why This Structure?**

1. **Generic Proxy network filter** intercepts all TCP data first
2. **HTTP/1.1 codec** parses raw HTTP into `RequestHeaderFrame` and `RequestCommonFrame`
3. **Your filter** receives parsed frames (not raw TCP data)
4. **Terminal behavior** stops processing after handling reverse connection requests

## Data Flow

### **Complete Flow:**
```
Raw HTTP Data → Generic Proxy Network Filter → HTTP1 Codec → Your Terminal Filter → Connection Closed
```

### **Step-by-Step:**
1. **Raw HTTP arrives**: `POST /reverse_connections/request HTTP/1.1\r\n...`
2. **Generic Proxy intercepts**: Network filter receives the data
3. **HTTP1 codec parses**: Creates `RequestHeaderFrame` and `RequestCommonFrame`
4. **Your filter processes**: `decodeHeaderFrame()` then `decodeCommonFrame()`
5. **Terminal behavior**: Returns `StopIteration`, closes connection
6. **No further processing**: Connection is closed, no more filters run

## Key Benefits

### **1. Terminal Filter Behavior**
- ✅ **Stops processing** after handling reverse connection requests
- ✅ **Closes connections** automatically
- ✅ **No downstream filters** run after your filter

### **2. Protocol-Agnostic Operation**
- ✅ **Works with HTTP, gRPC, or any custom protocol**
- ✅ **Same filter logic** across all protocols
- ✅ **Future-proof architecture**

### **3. Zero Protocol Parsing**
- ✅ **100% reuse** of Generic Proxy's parsing logic
- ✅ **No manual HTTP state machines** or CRLF searching
- ✅ **Automatic protocol compliance** guaranteed

### **4. Standard Envoy Patterns**
- ✅ **Follows Envoy's filter architecture** exactly
- ✅ **Built-in observability** and metrics
- ✅ **Production-ready infrastructure**

## What Generic Proxy Provides

### **1. Complete Protocol Support**
- **HTTP/1.1, HTTP/2, HTTP/3** parsing and encoding
- **gRPC** support with streaming
- **Custom protocols** via codec interface
- **Protocol evolution** handled automatically

### **2. Stream Management**
- **Automatic stream multiplexing** for concurrent requests
- **Frame routing** to correct streams
- **Connection lifecycle** management

### **3. Production-Ready Features**
- **Automatic error handling** and recovery
- **Protocol validation** and sanitization
- **Built-in observability** and metrics

## Implementation Details

### **Filter Registration**
```cpp
// Register as Generic Proxy filter, not network filter
REGISTER_FACTORY(ReverseConnFilterConfigFactory, GenericProxy::NamedFilterConfigFactory);
```

### **Terminal Filter Implementation**
```cpp
class ReverseConnFilter : public GenericProxy::StreamFilter {
public:
  // This makes it a terminal filter
  bool isTerminalFilter() const { return true; }
  
  // Process parsed frames (not raw TCP data)
  GenericProxy::HeaderFilterStatus decodeHeaderFrame(GenericProxy::RequestHeaderFrame& request) override;
  GenericProxy::CommonFilterStatus decodeCommonFrame(GenericProxy::RequestCommonFrame& request) override;
};
```

### **Connection Management**
```cpp
void ReverseConnFilter::processReverseConnectionRequest() {
  // Send acceptance response
  sendLocalReply(GenericProxy::Status::Ok, response_body);
  
  // Save the connection
  saveDownstreamConnection(node_uuid_, cluster_uuid_);
  
  // Close the connection after processing (terminal filter behavior)
  closeConnection();
}
```

## Summary

This filter is a **Generic Proxy L7 filter** (not a network filter) that:

1. **Runs inside Generic Proxy framework** - receives parsed HTTP frames, not raw TCP
2. **Acts as a terminal filter** - stops processing and closes connections after handling requests
3. **Works with HTTP/1.1 codec** - automatically parses HTTP into usable frames
4. **Follows standard patterns** - integrates seamlessly with Generic Proxy infrastructure

The key insight is that **Generic Proxy handles all the HTTP parsing and stream management**, while your filter just processes the parsed data and acts as a terminal point in the filter chain. 