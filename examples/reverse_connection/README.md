# Running the Sandbox for reverse tunnels

## Steps to run sandbox

1. Build envoy with reverse tunnels feature:
   - ```./ci/run_envoy_docker.sh './ci/do_ci.sh bazel.release.server_only'```
2. Build envoy docker image:
   - ```docker build -f ci/Dockerfile-envoy-image -t envoy:latest .```
3. Launch test containers.
   - ```docker-compose -f examples/reverse_connection/docker-compose.yaml up```

   **Note**: The docker-compose maps the following ports:
   - **downstream-envoy**: Host port 9000 → Container port 9000 (reverse connection API)
   - **upstream-envoy**: Host port 9001 → Container port 9000 (reverse connection API)

4. The reverse example configuration in initiator-envoy.yaml initiates reverse tunnels to upstream envoy using a custom address resolver. The configuration includes:

   ```yaml    
   # Bootstrap extension for reverse tunnel functionality
   bootstrap_extensions:
   - name: envoy.bootstrap.reverse_tunnel.downstream_socket_interface
   typed_config:
      "@type": type.googleapis.com/envoy.extensions.bootstrap.reverse_tunnel.downstream_socket_interface.v3.DownstreamReverseConnectionSocketInterface
      stat_prefix: "downstream_reverse_connection"

   # Reverse connection listener with custom address format
   - name: reverse_conn_listener
   address:
      socket_address:
         # Format: rc://src_node_id:src_cluster_id:src_tenant_id@remote_cluster:connection_count
          address: "rc://downstream-node:downstream-cluster:downstream-tenant@upstream-cluster:1"
         port_value: 0
         resolver_name: "envoy.resolvers.reverse_connection"
   ```

5. Test reverse tunnel:
   - Perform http request for the service behind downstream envoy, to upstream-envoy. This request will be sent
   over a reverse tunnel.

   ```bash
   [basundhara.c@basundhara-c envoy-examples]$ curl -H "x-remote-node-id: downstream-node" -H "x-dst-cluster-uuid: downstream-cluster" http://localhost:8085/downstream_service -v
   *   Trying ::1...
   * TCP_NODELAY set
   * Connected to localhost (::1) port 8085 (#0)
   > GET /downstream_service HTTP/1.1
   > Host: localhost:8085
   > User-Agent: curl/7.61.1
   > Accept: */*
   > x-remote-node-id: downstream-node
   > x-dst-cluster-uuid: downstream-cluster
   > 
   < HTTP/1.1 200 OK
   < server: envoy
   < date: Thu, 25 Sep 2025 21:25:38 GMT
   < content-type: text/plain
   < content-length: 159
   < expires: Thu, 25 Sep 2025 21:25:37 GMT
   < cache-control: no-cache
   < x-envoy-upstream-service-time: 13
   < 
   Server address: 172.27.0.3:80
   Server name: b490f264caf9
   Date: 25/Sep/2025:21:25:38 +0000
   URI: /downstream_service
   Request ID: 41807e3cd1f6a0b601597b80f7e51513
   * Connection #0 to host localhost left intact
   ``` 