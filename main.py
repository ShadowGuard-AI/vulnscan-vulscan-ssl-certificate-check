import argparse
import ipaddress
import logging
import ssl
import socket
import sys
from datetime import datetime, timezone
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Checks the SSL/TLS certificate of a given host. The certificate is fetched without verification so that self-signed, expired, and name-mismatched certificates can be inspected; chain trust, hostname match, and date validity are then reported as separate findings. Nothing is trusted on the back of the inspection connection.")
    parser.add_argument("host", type=str, help="The hostname or IP address to check.")
    parser.add_argument("-p", "--port", type=int, default=443, help="The port to connect to (default: 443).")
    parser.add_argument("--ca-file", type=str, default=None, help="Optional PEM file with additional CA certificates to trust for the separate chain verification check (for example a private or fixture CA). The system trust store is always used as well.")
    return parser.parse_args()


def make_inspection_context():
    """Build the non-verifying context used to fetch a certificate for
    inspection. Verification is off for this fetch only, so a bad
    certificate can be examined; no trust decision uses this context."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _connect(host, port, context, server_hostname=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)  # Set a timeout to avoid indefinite blocking
    sock.connect((host, port))
    try:
        return context.wrap_socket(sock, server_hostname=server_hostname if server_hostname is not None else host)
    except Exception:
        sock.close()
        raise


def get_ssl_certificate(host, port):
    """
    Retrieves the SSL/TLS certificate from a given host and port without
    enforcing validity, so self-signed, expired, and mismatched
    certificates are returned for inspection instead of collapsing into
    a retrieval failure.

    Args:
        host (str): The hostname or IP address.
        port (int): The port to connect to.

    Returns:
        tuple: (crypto.X509 certificate, DER bytes) or None on failure.
    """
    ssl_sock = None
    try:
        ssl_sock = _connect(host, port, make_inspection_context())
        cert_der = ssl_sock.getpeercert(binary_form=True)
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
        return cert, cert_der
    except socket.timeout:
        logging.error(f"Connection to {host}:{port} timed out.")
        return None
    except socket.gaierror:
        logging.error(f"Could not resolve hostname: {host}")
        return None
    except ConnectionRefusedError:
        logging.error(f"Connection refused to {host}:{port}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None
    finally:
        if ssl_sock is not None:
            ssl_sock.close()


def check_chain_trust(host, port, ca_file=None):
    """
    Separately verifies the chain and hostname with a fully verifying
    connection, the way a client would judge this server.

    Returns:
        tuple: (trusted, reason). trusted is True only when a verifying
        handshake succeeds; reason carries the verification error text
        when it does not.
    """
    ssl_sock = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca_file:
            context.load_verify_locations(cafile=ca_file)
        ssl_sock = _connect(host, port, context)
        return True, None
    except ssl.SSLCertVerificationError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)
    finally:
        if ssl_sock is not None:
            ssl_sock.close()


def _parse_asn1_time(raw):
    """Parse a pyOpenSSL ASN.1 time value (bytes) into an aware UTC datetime."""
    text = raw.decode("ascii") if isinstance(raw, bytes) else str(raw)
    for fmt in ("%Y%m%d%H%M%SZ", "%y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized certificate time format: {text}")


def check_certificate_validity(cert):
    """
    Checks the date window of the certificate against the current UTC time.

    Args:
        cert (crypto.X509): The SSL/TLS certificate object.

    Returns:
        tuple: (state, expiry_date, days_to_expiry) where state is one of
        "valid", "expired", "not_yet_valid", or None on failure.
    """
    if not cert:
        return None, None, None

    try:
        not_before = _parse_asn1_time(cert.get_notBefore())
        not_after = _parse_asn1_time(cert.get_notAfter())
        now = datetime.now(timezone.utc)
        if now < not_before:
            return "not_yet_valid", not_after, None
        if now > not_after:
            return "expired", not_after, None
        return "valid", not_after, (not_after - now).days
    except Exception as e:
        logging.error(f"Error during certificate validity check: {e}")
        return None, None, None


def _dns_matches(pattern, host):
    pattern = pattern.lower()
    host = host.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if not host.endswith(suffix):
            return False
        leftmost = host[: -len(suffix)]
        return leftmost != "" and "." not in leftmost
    return pattern == host


def check_hostname_match(cert_der, common_name, host):
    """
    Computes whether the certificate names the requested host, from its
    subject alternative names (DNS or IP) or, with no SANs, its subject
    common name. Returns True, False, or None when it cannot be decided.
    """
    try:
        cert_crypto = x509.load_der_x509_certificate(cert_der, default_backend())
        try:
            san_ext = cert_crypto.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except Exception:
            san_ext = None
        if san_ext is not None:
            try:
                host_ip = ipaddress.ip_address(host)
            except ValueError:
                host_ip = None
            if host_ip is not None:
                ip_sans = san_ext.value.get_values_for_type(x509.IPAddress)
                return any(ip == host_ip for ip in ip_sans)
            dns_sans = san_ext.value.get_values_for_type(x509.DNSName)
            return any(_dns_matches(name, host) for name in dns_sans)
        if common_name:
            return _dns_matches(common_name, host)
        return None
    except Exception as e:
        logging.error(f"Error during hostname match check: {e}")
        return None


def get_certificate_ciphers(host, port):
    """
    Retrieves the cipher negotiated on a fresh inspection connection
    (verification off, as in get_ssl_certificate).

    Returns:
        list: A one item list with the negotiated cipher tuple, or None.
    """
    ssl_sock = None
    try:
        ssl_sock = _connect(host, port, make_inspection_context())
        cipher = ssl_sock.cipher()
        return [cipher]
    except socket.timeout:
        logging.error(f"Connection to {host}:{port} timed out.")
        return None
    except socket.gaierror:
        logging.error(f"Could not resolve hostname: {host}")
        return None
    except ConnectionRefusedError:
        logging.error(f"Connection refused to {host}:{port}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None
    finally:
        if ssl_sock is not None:
            ssl_sock.close()


def get_certificate_details(cert):
    """
    Extracts and prints relevant details from the certificate.

    Args:
        cert (crypto.X509): The SSL/TLS certificate object.
    """
    if not cert:
        logging.error("No certificate provided for details extraction.")
        return
    try:
        subject = cert.get_subject()
        common_name = subject.CN

        issuer = cert.get_issuer()
        issuer_common_name = issuer.CN

        serial_number = cert.get_serial_number()

        cert_algorithm = cert.get_signature_algorithm()

        fingerprint_sha1 = cert.digest('sha1').decode('utf-8')
        fingerprint_sha256 = cert.digest('sha256').decode('utf-8')

        cert_crypto = x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert), default_backend())

        dns_sans = []
        ip_sans = []
        try:
            san_extensions = cert_crypto.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_sans = san_extensions.value.get_values_for_type(x509.DNSName)
            ip_sans = [str(ip) for ip in san_extensions.value.get_values_for_type(x509.IPAddress)]
        except Exception:
            dns_sans = []
            ip_sans = []

        logging.info("Certificate Details:")
        logging.info(f"  Subject Common Name: {common_name}")
        logging.info(f"  Issuer Common Name: {issuer_common_name}")
        logging.info(f"  Serial Number: {serial_number}")
        logging.info(f"  Signature Algorithm: {cert_algorithm}")
        logging.info(f"  Fingerprint (SHA1): {fingerprint_sha1}")
        logging.info(f"  Fingerprint (SHA256): {fingerprint_sha256}")
        if dns_sans:
            logging.info(f"  Subject Alternative Names (DNS): {', '.join(dns_sans)}")
        if ip_sans:
            logging.info(f"  Subject Alternative Names (IP): {', '.join(ip_sans)}")

    except Exception as e:
        logging.error(f"Error extracting certificate details: {e}")


def main():
    """
    Main function to execute the SSL/TLS certificate check.

    Returns an exit code: 0 when a certificate was retrieved and the
    check completed (whatever its findings), 1 on an invalid port or
    when no certificate could be retrieved.
    """
    args = setup_argparse()
    host = args.host
    port = args.port

    if not isinstance(port, int) or port <= 0 or port > 65535:
        logging.error("Invalid port number. Please provide a valid port number between 1 and 65535.")
        return 1

    logging.info(f"Checking SSL certificate for {host}:{port}")
    logging.info("Fetching the certificate without verification, for inspection only; trust findings below come from a separate verifying connection.")

    fetched = get_ssl_certificate(host, port)

    if not fetched:
        logging.error(f"Failed to retrieve SSL certificate for {host}:{port}")
        return 1

    cert, cert_der = fetched

    state, expiry_date, days_to_expiry = check_certificate_validity(cert)
    if state == "valid":
        logging.info("Date validity: certificate is within its validity window.")
        if expiry_date and days_to_expiry is not None:
            logging.info(f"Certificate expires on: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')} UTC (in {days_to_expiry} days)")
    elif state == "expired":
        logging.warning("Date validity: certificate has EXPIRED.")
        if expiry_date:
            logging.warning(f"Certificate expired on: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    elif state == "not_yet_valid":
        logging.warning("Date validity: certificate is not yet valid.")
        if expiry_date:
            logging.warning(f"Certificate expires on: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    else:
        logging.warning("Date validity: could not be determined.")

    subject = cert.get_subject()
    hostname_match = check_hostname_match(cert_der, subject.CN if subject else None, host)
    if hostname_match is True:
        logging.info(f"Hostname match: certificate names {host}.")
    elif hostname_match is False:
        logging.warning(f"Hostname match: certificate does NOT name {host}.")
    else:
        logging.warning("Hostname match: could not be determined.")

    trusted, trust_reason = check_chain_trust(host, port, args.ca_file)
    if trusted:
        logging.info("Chain trust: a verifying connection succeeded; the chain is trusted.")
    else:
        logging.warning(f"Chain trust: NOT trusted. Verification failed: {trust_reason}")

    ciphers = get_certificate_ciphers(host, port)
    if ciphers:
        logging.info(f"Cipher negotiated on the inspection connection: {', '.join([cipher[0] for cipher in ciphers])}")

    get_certificate_details(cert)
    return 0


if __name__ == "__main__":
    sys.exit(main())
