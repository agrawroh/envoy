QUIC downstream listeners with ``require_client_certificate: true`` now require an explicit
``validation_context.trusted_ca`` and reject ``trust_chain_verification: ACCEPT_UNTRUSTED``.
Configurations missing a trust anchor or set to ``ACCEPT_UNTRUSTED`` previously failed at
startup with ``TLS Client Authentication is not supported over QUIC`` (the entire feature
was rejected). They now fail with a more specific error pointing at the missing trust anchor.
