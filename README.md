# vulnscan-vulscan-ssl-certificate-check
Checks the SSL/TLS certificate of a given host and reports on its validity, expiry, and the cipher negotiated.

How inspection works, stated plainly: connections to the target are made without verification so that bad certificates can be examined. The fetched certificate is never trusted on the back of that connection. Instead, the tool reports three separate findings computed from the fetched certificate and from a second, fully verifying connection: date validity (within its window, expired, or not yet valid), hostname match (whether the certificate names the host, from its subject alternative names or common name), and chain trust (whether a verifying client connection succeeds, and the verification error when it does not). Self-signed, expired, and name-mismatched certificates each get a full report with their details instead of a retrieval failure.

## Install
`git clone https://github.com/ShadowGuardAI/vulnscan-vulscan-ssl-certificate-check`

## Usage
`./vulnscan-vulscan-ssl-certificate-check [params]`

The positional argument is the hostname or IP address to check.

## Parameters
- `-h`: Show help message and exit
- `-p`: The port to connect to (default: 443)
- `--ca-file`: Optional PEM file with additional CA certificates to trust for the separate chain verification check, for example a private CA. The system trust store is always used as well.

Exit codes: 0 when a certificate was retrieved and the check completed, whatever its findings. An invalid port, an unresolvable host, or a host from which no certificate can be retrieved exits non-zero with no verdict.

## License
Copyright (c) ShadowStrikeHQ
