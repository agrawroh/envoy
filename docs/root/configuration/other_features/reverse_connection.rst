.. _config_reverse_connection:

Reverse Connection
==================

Envoy supports reverse connections that enable re-using existing connectionns to access services behind a private network from behind a public network. This feature is designed to solve the challenge of accessing downstream services in private networks from applications behind a firewall or NAT.

Background
==========

The following is an environment where reverse connections are used:

* There are services behind downstream Envoy instances in a private network.
* There are services behind upstream Envoy instances in a public network. These services cannot access the services behind the downstream Envoy instances using forward connections but need to send requests to them using reverse connections.
* Downstream envoys initiate HTTPS connections to upstream envoy instances, following which upstream envoy caches the connection socket -> these are "reverse connections".
* When a request for a downstream service is received, the upstream Envoy picks an available "reverse connection" or cached connection socket for the downstream cluster and uses it to send the request.

.. image:: /_static/reverse_connection_concept.png
   :alt: Reverse Connection Architecture
   :align: center

Reverse Connection Workflow
===========================

The following sequence diagram illustrates the workflow for establishing and managing reverse connections:

.. image:: /_static/reverse_connection_workflow.png
   :alt: Reverse Connection Workflow
   :align: center

**Workflow Steps:**

1. **Create Reverse Connection Listener**: On downstream envoy, reverse connections are initiated by the addition of a reverse connection listener via a LDS update. This makes it easy to pass metadata identifying source Envoy and the remote clusters and reverse tunnel count to each cluster. The upstream clusters are dynamically configurable via CDS.
2. **Initiate Reverse Connections**: The listener calls the reverse connection workflow and initiates raw TCP connections to upstream clusters. This triggers the reverse connection handshake where downstream Envoy should passes metadata identifying itself (node ID, cluster ID) in the reverse connection request. Upstream Envoy will use this to index and store sockets for each downstream node ID by node ID.
3. **Map Connections**: Upstream Envoy accepts the reverse connection handshake and stores the TCP socket mapped to the downstream node ID.
4. **Keepalive**: Reverse connections are long lived connections between downstream and upstream Envoy. Once established, there is a keepalive mechanism to detect connection closure.
6. **Request Routing**: When upstream envoy receives a request that needs to be sent to a downstream service, specific headers indicate which downstream node the request needs to be sent to. Upstream envoy picks a cached socket for the downstream node and sends the request over it.
7. **Connection Closure and Re-initiation**: If a cached reverse connection socket closes on either downstream or upstream envoy, envoy detects it and downstream envoy re-initiates the reverse connection.
