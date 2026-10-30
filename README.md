# Generic ARM WireGuard-over-WebSocket client

Client for wstunnel v10 UDP forwarding. Server hostname, TLS name, path and DER trust certificate are supplied at runtime:

    wsudp PORT SERVER TLS_NAME PATH CA_DER

No device credentials or certificates are included. Kernel modules are built against the SDK of the matching AC6 image.
