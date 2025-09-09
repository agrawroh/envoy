# Reverse Tunnels Admin Interface Examples

## Overview

The enhanced `/reverse_tunnels` admin interface provides comprehensive monitoring and filtering capabilities for reverse tunnel connections in Envoy. This document provides practical examples of using the API with various filtering, sorting, and formatting options.

## Basic Usage

### Get All Reverse Tunnel Connections

```bash
curl http://localhost:9901/reverse_tunnels
```

**Response (JSON format):**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "summary": {
    "total_connections": 150,
    "healthy_connections": 145,
    "unhealthy_connections": 5,
    "unique_nodes": 50,
    "unique_clusters": 3,
    "unique_tenants": 10
  },
  "aggregations": {
    "by_node": {
      "node-001": 3,
      "node-002": 2
    },
    "by_cluster": {
      "cluster-west": 75,
      "cluster-east": 75
    },
    "by_tenant": {
      "tenant-a": 30,
      "tenant-b": 120
    },
    "by_worker": {
      "worker_0": 50,
      "worker_1": 50,
      "worker_2": 50
    }
  },
  "connections": [
    {
      "node_id": "node-001",
      "cluster_id": "cluster-west",
      "tenant_id": "tenant-a",
      "remote_address": "10.0.1.5:45678",
      "local_address": "10.0.0.1:8080",
      "established_time": "2024-01-15T09:00:00Z",
      "last_activity": "2024-01-15T10:29:55Z",
      "last_ping_sent": "2024-01-15T10:29:50Z",
      "last_ping_received": "2024-01-15T10:29:55Z",
      "is_healthy": true,
      "worker_thread": "worker_0",
      "bytes_sent": 1048576,
      "bytes_received": 524288,
      "consecutive_ping_failures": 0,
      "total_pings_sent": 120,
      "total_pings_received": 119
    }
  ]
}
```

## Filtering Examples

### Filter by Node ID

```bash
curl "http://localhost:9901/reverse_tunnels?node_id=node-001"
```

Shows only connections from the specified node.

### Filter by Cluster ID

```bash
curl "http://localhost:9901/reverse_tunnels?cluster_id=cluster-west"
```

Shows only connections from nodes in the specified cluster.

### Filter by Health Status

```bash
# Show only healthy connections
curl "http://localhost:9901/reverse_tunnels?health=healthy"

# Show only unhealthy connections
curl "http://localhost:9901/reverse_tunnels?health=unhealthy"

# Show all connections (default)
curl "http://localhost:9901/reverse_tunnels?health=all"
```

### Regular Expression Filtering

```bash
# Find all connections containing "prod" in node, cluster, or tenant ID
curl "http://localhost:9901/reverse_tunnels?filter=prod"

# Find connections from nodes starting with "web-"
curl "http://localhost:9901/reverse_tunnels?filter=^web-"

# Find connections with cluster IDs ending in "-east"
curl "http://localhost:9901/reverse_tunnels?filter=east$"
```

### Time Range Filtering

```bash
# Connections established in the last hour
curl "http://localhost:9901/reverse_tunnels?since=2024-01-15T09:30:00Z"

# Connections in a specific time window
curl "http://localhost:9901/reverse_tunnels?since=2024-01-15T08:00:00Z&until=2024-01-15T10:00:00Z"
```

### Combined Filtering

```bash
# Healthy connections from production clusters established recently
curl "http://localhost:9901/reverse_tunnels?filter=prod&health=healthy&since=2024-01-15T09:00:00Z"
```

## Sorting Examples

### Sort by Different Fields

```bash
# Sort by node ID (ascending - default)
curl "http://localhost:9901/reverse_tunnels?sort_by=node_id"

# Sort by cluster ID (descending)
curl "http://localhost:9901/reverse_tunnels?sort_by=cluster_id&desc=true"

# Sort by connection age (newest first)
curl "http://localhost:9901/reverse_tunnels?sort_by=established_time&desc=true"

# Sort by recent activity
curl "http://localhost:9901/reverse_tunnels?sort_by=last_activity&desc=true"

# Sort by ping latency (highest first)
curl "http://localhost:9901/reverse_tunnels?sort_by=ping_latency&desc=true"

# Sort by failure count (most problematic first)
curl "http://localhost:9901/reverse_tunnels?sort_by=failures&desc=true"
```

## Output Format Examples

### JSON Format (Default)

```bash
curl "http://localhost:9901/reverse_tunnels?format=json"
```

Structured data suitable for programmatic consumption.

### Text Format

```bash
curl "http://localhost:9901/reverse_tunnels?format=text"
```

**Response:**
```
Reverse Tunnel Connections
==========================
Generated: 2024-01-15T10:30:00Z

Summary:
  Total Connections: 150
  Healthy: 145
  Unhealthy: 5
  Unique Nodes: 50
  Unique Clusters: 3
  Unique Tenants: 10

Connections by Cluster:
  cluster-west: 75
  cluster-east: 75

Connection Details:
NodeID   | ClusterID    | TenantID | Remote -> Local              | Health  | Worker
---------|--------------|----------|------------------------------|---------|--------
node-001 | cluster-west | tenant-a | 10.0.1.5:45678 -> 10.0.0.1  | HEALTHY | worker_0
node-002 | cluster-west | tenant-a | 10.0.1.6:45679 -> 10.0.0.1  | HEALTHY | worker_1
```

### Prometheus Format

```bash
curl "http://localhost:9901/reverse_tunnels?format=prometheus"
```

**Response:**
```
# HELP envoy_reverse_tunnels_total Total number of reverse tunnel connections
# TYPE envoy_reverse_tunnels_total gauge
envoy_reverse_tunnels_total 150

# HELP envoy_reverse_tunnels_healthy Number of healthy reverse tunnel connections
# TYPE envoy_reverse_tunnels_healthy gauge
envoy_reverse_tunnels_healthy 145

# HELP envoy_reverse_tunnels_unhealthy Number of unhealthy reverse tunnel connections
# TYPE envoy_reverse_tunnels_unhealthy gauge
envoy_reverse_tunnels_unhealthy 5

# HELP envoy_reverse_tunnels_by_cluster Reverse tunnel connections by cluster
# TYPE envoy_reverse_tunnels_by_cluster gauge
envoy_reverse_tunnels_by_cluster{cluster="cluster-west"} 75
envoy_reverse_tunnels_by_cluster{cluster="cluster-east"} 75

# HELP envoy_reverse_tunnels_by_node Reverse tunnel connections by node
# TYPE envoy_reverse_tunnels_by_node gauge
envoy_reverse_tunnels_by_node{node="node-001"} 3
envoy_reverse_tunnels_by_node{node="node-002"} 2

# HELP envoy_reverse_tunnels_by_tenant Reverse tunnel connections by tenant
# TYPE envoy_reverse_tunnels_by_tenant gauge
envoy_reverse_tunnels_by_tenant{tenant="tenant-a"} 30
envoy_reverse_tunnels_by_tenant{tenant="tenant-b"} 120
```

## Pagination Examples

### Basic Pagination

```bash
# First page (100 connections)
curl "http://localhost:9901/reverse_tunnels?limit=100&offset=0"

# Second page (next 100 connections)
curl "http://localhost:9901/reverse_tunnels?limit=100&offset=100"

# Get specific range
curl "http://localhost:9901/reverse_tunnels?limit=50&offset=200"
```

### Combined with Filtering

```bash
# First 20 healthy connections from cluster-west
curl "http://localhost:9901/reverse_tunnels?cluster_id=cluster-west&health=healthy&limit=20"
```

## Metadata Examples

### Basic Connection Information

```bash
curl "http://localhost:9901/reverse_tunnels"
```

Includes basic connection details without extended metadata.

### Detailed Metadata

```bash
curl "http://localhost:9901/reverse_tunnels?include_metadata=true"
```

**Additional fields in JSON response:**
```json
{
  "node_id": "node-001",
  "metadata": {
    "ping_interval_ms": 5000,
    "average_ping_latency_ms": 45
  }
}
```

## Monitoring Use Cases

### Dashboard Overview

```bash
# Summary statistics for dashboards
curl "http://localhost:9901/reverse_tunnels?aggregate_only=true&format=prometheus"
```

### Health Monitoring

```bash
# Check for unhealthy connections
curl "http://localhost:9901/reverse_tunnels?health=unhealthy&format=text"

# Monitor high-latency connections
curl "http://localhost:9901/reverse_tunnels?sort_by=ping_latency&desc=true&limit=10"
```

### Debugging Specific Issues

```bash
# Investigate connections from a specific node
curl "http://localhost:9901/reverse_tunnels?node_id=problematic-node&include_metadata=true"

# Find recent connection establishment patterns
curl "http://localhost:9901/reverse_tunnels?sort_by=established_time&desc=true&limit=50"

# Check for connection failures
curl "http://localhost:9901/reverse_tunnels?sort_by=failures&desc=true&health=unhealthy"
```

## Advanced Query Examples

### Complex Filtering

```bash
# Production connections with recent activity
curl "http://localhost:9901/reverse_tunnels?filter=prod&sort_by=last_activity&desc=true&limit=25"

# Connections with ping issues in the last 6 hours
curl "http://localhost:9901/reverse_tunnels?since=2024-01-15T04:30:00Z&sort_by=failures&desc=true&health=unhealthy"

# Cluster capacity analysis
curl "http://localhost:9901/reverse_tunnels?cluster_id=cluster-west&sort_by=established_time&format=text"
```

### Programmatic Integration

```bash
# Machine-readable format for scripts
curl -H "Accept: application/json" "http://localhost:9901/reverse_tunnels?aggregate_only=true" | jq '.summary.total_connections'

# Prometheus integration
curl "http://localhost:9901/reverse_tunnels?format=prometheus" | grep "envoy_reverse_tunnels_total"

# CSV-style output for analysis
curl "http://localhost:9901/reverse_tunnels?format=text" | grep -A 1000 "Connection Details:"
```

## Performance Considerations

### Large Result Sets

```bash
# Use pagination for large environments
curl "http://localhost:9901/reverse_tunnels?limit=100&offset=0"

# Aggregate view for overview
curl "http://localhost:9901/reverse_tunnels?aggregate_only=true"

# Filter early to reduce response size
curl "http://localhost:9901/reverse_tunnels?cluster_id=specific-cluster&limit=50"
```

### Monitoring Automation

```bash
# Regular health check script
curl -s "http://localhost:9901/reverse_tunnels?health=unhealthy&format=json" | \
  jq '.summary.unhealthy_connections' | \
  xargs -I {} sh -c 'if [ {} -gt 5 ]; then echo "ALERT: {} unhealthy connections"; fi'

# Prometheus scraping endpoint
curl "http://localhost:9901/reverse_tunnels?format=prometheus&aggregate_only=true"
```

## Query Parameter Reference

| Parameter | Type | Values | Description |
|-----------|------|--------|-------------|
| `node_id` | string | any | Filter by specific node ID |
| `cluster_id` | string | any | Filter by specific cluster ID |
| `tenant_id` | string | any | Filter by specific tenant ID |
| `format` | enum | json, text, prometheus | Output format |
| `health` | enum | all, healthy, unhealthy | Health status filter |
| `filter` | regex | any RE2 regex | Pattern matching filter |
| `since` | timestamp | ISO8601 | Show connections since timestamp |
| `until` | timestamp | ISO8601 | Show connections until timestamp |
| `sort_by` | enum | node_id, cluster_id, tenant_id, established_time, last_activity, ping_latency, failures | Sort field |
| `desc` | boolean | true, false | Sort in descending order |
| `limit` | integer | 1-10000 | Maximum connections to return |
| `offset` | integer | ≥0 | Skip first N connections |
| `aggregate_only` | boolean | true, false | Return only summary stats |
| `include_metadata` | boolean | true, false | Include detailed metadata |

## Error Handling

### Invalid Parameters

```bash
# Invalid format
curl "http://localhost:9901/reverse_tunnels?format=invalid"
# Returns: HTTP 400 - Invalid format parameter

# Invalid regex
curl "http://localhost:9901/reverse_tunnels?filter=[invalid"
# Returns: HTTP 400 - Invalid re2 regex

# Invalid timestamp
curl "http://localhost:9901/reverse_tunnels?since=invalid-time"
# Returns: HTTP 400 - Invalid 'since' timestamp format
```

### Large Limit Values

```bash
# Limit too large
curl "http://localhost:9901/reverse_tunnels?limit=50000"
# Returns: HTTP 400 - Limit parameter too large. Maximum is 10000.
```

## Integration with Monitoring Systems

### Grafana Dashboard Query

```bash
# Prometheus metrics for Grafana
curl "http://localhost:9901/reverse_tunnels?format=prometheus&aggregate_only=true"
```

### Alerting Rules

```bash
# Check for connection health issues
UNHEALTHY=$(curl -s "http://localhost:9901/reverse_tunnels?aggregate_only=true" | jq '.summary.unhealthy_connections')
if [ $UNHEALTHY -gt 10 ]; then
  echo "CRITICAL: $UNHEALTHY unhealthy reverse tunnel connections"
fi

# Monitor connection growth
TOTAL=$(curl -s "http://localhost:9901/reverse_tunnels?aggregate_only=true" | jq '.summary.total_connections')
if [ $TOTAL -gt 1000 ]; then
  echo "WARNING: High reverse tunnel connection count: $TOTAL"
fi
```

### Log Analysis Integration

```bash
# Export connection details for analysis
curl "http://localhost:9901/reverse_tunnels?format=text&sort_by=last_activity&desc=true" > reverse_tunnels_snapshot.txt

# JSON export for data processing
curl "http://localhost:9901/reverse_tunnels?include_metadata=true" | jq '.connections[] | select(.consecutive_ping_failures > 0)' > problematic_connections.json
```

## Troubleshooting Scenarios

### Connection Issues

```bash
# Find connections with high failure rates
curl "http://localhost:9901/reverse_tunnels?sort_by=failures&desc=true&limit=10&format=text"

# Check recent connection patterns
curl "http://localhost:9901/reverse_tunnels?sort_by=established_time&desc=true&limit=20&since=2024-01-15T00:00:00Z"
```

### Performance Analysis

```bash
# High latency connections
curl "http://localhost:9901/reverse_tunnels?sort_by=ping_latency&desc=true&include_metadata=true&limit=5"

# Worker thread distribution
curl "http://localhost:9901/reverse_tunnels?aggregate_only=true" | jq '.aggregations.by_worker'
```

### Capacity Planning

```bash
# Cluster utilization analysis
curl "http://localhost:9901/reverse_tunnels?format=text" | grep "Connections by Cluster"

# Node connection density
curl "http://localhost:9901/reverse_tunnels?aggregate_only=true" | jq '.aggregations.by_node | to_entries | sort_by(.value) | reverse | .[0:10]'
```

## Best Practices

### Regular Monitoring

1. **Health Checks**: Monitor unhealthy connection count regularly
2. **Capacity Monitoring**: Track total connections and per-cluster distribution
3. **Performance Monitoring**: Watch for high latency or failure patterns

### Efficient Querying

1. **Use Filtering**: Apply filters early to reduce response size
2. **Pagination**: Use limit and offset for large result sets
3. **Aggregate Views**: Use `aggregate_only=true` for overview dashboards
4. **Targeted Queries**: Filter by specific nodes or clusters when debugging

### Response Size Management

1. **Avoid Large Unfiltered Queries**: Always use appropriate limits
2. **Metadata on Demand**: Only use `include_metadata=true` when needed
3. **Format Selection**: Use Prometheus format for metrics, text for human readability

This comprehensive API provides powerful capabilities for monitoring, debugging, and managing reverse tunnel connections in Envoy environments.
