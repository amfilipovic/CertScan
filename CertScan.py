import argparse
import concurrent.futures
import logging
import socket
import ssl
import time
import warnings
from datetime import datetime, timezone
import pandas as pd
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm

scan_start_time = datetime.now().strftime('%Y%m%d-%H%M%S')
log_filename = f"CertScan_{scan_start_time}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
warnings.filterwarnings("ignore", category=UserWarning, module="cryptography")

def scan_domain_certificate(domain, port, timeout, retries, delay):
    for attempt in range(retries + 1):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as conn:
                conn.settimeout(timeout)
                with context.wrap_socket(conn, server_hostname=domain) as sock:
                    cert = sock.getpeercert(binary_form=True)
                    if not cert:
                        raise ValueError("No certificate received.")
                    try:
                        with warnings.catch_warnings(record=True) as w:
                            warnings.simplefilter("always", category=UserWarning)
                            x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                            for warning in w:
                                logging.warning(f"Cryptography warning for {domain}: {warning.message}")
                    except ValueError:
                        logging.warning(f"Invalid certificate for {domain}")
                        return {"Domain": domain, "Port": port, "Error": "Invalid certificate"}
                    if x509_cert.serial_number < 0:
                        logging.warning(f"Certificate for {domain} has a negative serial number, which is disallowed by RFC 5280.")
                        return {"Domain": domain, "Port": port, "Error": "Negative serial number"}
                    expiry_date = x509_cert.not_valid_after_utc
                    days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                    is_self_signed_flag = False
                    if x509_cert.issuer == x509_cert.subject:
                        for ext in x509_cert.extensions:
                            if (
                                isinstance(ext.value, x509.BasicConstraints)
                                and ext.value.ca
                                and ext.critical
                            ):
                                is_self_signed_flag = True
                                break
                    cipher_info = sock.cipher() or ("Unknown", "Unknown", "Unknown")
                    report = {
                        "Domain": domain,
                        "Port": port,
                        "Issuer": x509_cert.issuer.rfc4514_string(),
                        "Subject": x509_cert.subject.rfc4514_string(),
                        "Expiry date": expiry_date.isoformat(),
                        "Days until expiry": days_until_expiry,
                        "Is expired": days_until_expiry < 0,
                        "Is self-signed": is_self_signed_flag,
                        "SSL/TLS version": sock.version() or "Unknown",
                        "Cipher suite": cipher_info[0],
                        "Protocol version": cipher_info[1],
                        "Key exchange": cipher_info[2],
                        "Trusted CA": not is_self_signed_flag,
                    }
                    logging.info(f"Analyzed {domain}:{port} - Expiry: {expiry_date}, Self-signed: {is_self_signed_flag}")
                    return report
        except ssl.SSLError as e:
            logging.error(f"SSL error for {domain}:{port} (attempt {attempt + 1}/{retries + 1}): {e}")
        except socket.timeout:
            logging.error(f"Timeout for {domain}:{port} (attempt {attempt + 1}/{retries + 1})")
        except Exception as e:
            logging.error(f"Unexpected error analyzing {domain}:{port} (attempt {attempt + 1}/{retries + 1}): {e}")
        if attempt < retries:
            time.sleep(delay)
    return {"Domain": domain, "Port": port, "Error": f"Failed after {retries} attempts"}

def main():
    parser = argparse.ArgumentParser(description="Certificate Scanner")
    parser.add_argument("-a", "--address", help="Single domain to analyze")
    parser.add_argument("-l", "--list", help="File containing a list of domains")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port to scan (default: 443)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for each connection attempt")
    parser.add_argument("-r", "--retries", type=int, default=3, help="Number of retries for failed connections")
    parser.add_argument("-d", "--delay", type=int, default=1, help="Delay between retries in seconds")
    parser.add_argument("-w", "--workers", type=int, default=1, help="Number of concurrent workers")
    parser.add_argument("-o", "--output", default="CertScan", help="Report file name prefix")
    args = parser.parse_args()
    domains = set()
    if args.address:
        domains.add(args.address.strip())
    if args.list:
        try:
            with open(args.list, "r") as file:
                for line in file:
                    domains.add(line.strip())
        except FileNotFoundError:
            logging.error(f"File not found: {args.list}")
            return
    if not domains:
        logging.error("No valid domains specified.")
        return
    logging.info("Scan started.")
    reports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_domain = {
            executor.submit(scan_domain_certificate, domain, args.port, args.timeout, args.retries, args.delay): domain
            for domain in domains
        }
        with tqdm(total=len(domains), desc="Analyzing domains", unit="dom.") as pbar:
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    reports.append(future.result())
                except Exception as e:
                    logging.error(f"Error analyzing {domain}: {e}")
                pbar.update(1)
    if reports:
        output_file = f"{args.output}_{scan_start_time}.xlsx"
        pd.DataFrame(reports).to_excel(output_file, index=False)
        logging.info("Scan completed.")

if __name__ == "__main__":
    main()
