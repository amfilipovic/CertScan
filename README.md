# CertScan

## Overview

The CertScan (`CertScan.py`) is a Python script designed to analyze SSL/TLS certificates of a single domain or from a list of domains. It retrieves and evaluates certificate details such as expiration dates, issuer, cipher suite, and self-signed status. It supports multi-threaded scanning and exports results to an Excel file.

## Files

1. `CertScan.py`: The main script containing the certificate scanning logic.
2. `CertScan_YYYYMMDD-HHMMSS.log`: Log file generated during execution.
3. `CertScan_YYYYMMDD-HHMMSS.xlsx`: Output report containing certificate details.

## Dependencies

- Python standard libraries: `argparse`, `socket`, `ssl`, `time`, `logging`, `concurrent.futures`, `warnings`
- External libraries:
  - `cryptography` (for certificate parsing)
  - `pandas` (for report generation)
  - `tqdm` (for progress tracking)

## Functions and Logic

### `scan_domain_certificate`

- **Purpose:** Connects to a domain via SSL/TLS and retrieves certificate details.
- **Logic:**
  - Establishes an SSL connection to the given domain and port.
  - Extracts certificate information using `cryptography.x509`.
  - Checks if the certificate is expired, self-signed, or has a valid issuer.
  - Logs any SSL/TLS errors encountered.
  - Returns a structured report including expiry date, cipher suite, and certificate details.

### `main`

- **Purpose:** Handles user input, manages parallel execution, and generates reports.
- **Logic:**
  - Parses command-line arguments.
  - Reads domains from user input or a file.
  - Uses `ThreadPoolExecutor` for concurrent domain analysis.
  - Saves the results to an Excel file using `pandas`.
  - Logs errors and progress updates.

## Usage

### Command-line Arguments

| Argument | Description |
|----------|-------------|
| `-a`, `--address` | Single domain to analyze. |
| `-l`, `--list` | File containing multiple domains. |
| `-p`, `--port` | Port to scan (default: 443). |
| `-t`, `--timeout` | Timeout per connection attempt (default: 5s). |
| `-r`, `--retries` | Number of retries per domain (default: 3). |
| `-d`, `--delay` | Delay between retries (default: 1s). |
| `-w`, `--workers` | Number of concurrent workers (default: 1). |
| `-o`, `--output` | Prefix for the output file name. |

### Running the script

Scan a single domain:

```sh
python CertScan.py -a example.com
```

Scan multiple domains from a file with five workers:

```sh
python CertScan.py -l domains.txt -w 5
```

## Output

- **Log File (`CertScan_YYYYMMDD-HHMMSS.log`)**: Stores detailed logs of each scan attempt.
- **Excel Report (`CertScan_YYYYMMDD-HHMMSS.xlsx`)**: Contains a summary of certificate details for each domain scanned.

## Example Excel Report

| Domain | Port | Issuer | Subject | Expiry date | Days until expiry | Is expired | Is self-signed | SSL/TLS version | Cipher suite | Protocol version | Key exchange | Trusted CA |
| ------ | ---- | ------ | ------- | ----------- | ----------------- | ---------- | -------------- | --------------- | ------------ | ---------------- | ------------ | ---------- |
| example.com | 443 | CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US | CN=*.example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US | 2026-01-15T23:59:59+00:00 | 316 | FALSE | FALSE | TLSv1.3 | TLS_AES_256_GCM_SHA384 | TLSv1.3 | 256 | TRUE |

## Notes

- Self-signed certificates are marked as **"Is self-signed = TRUE"**.
- Expired certificates are flagged as **"Is expired = TRUE"**.
- The scan may take longer depending on the number of domains, timeouts, retries, delays and workers used.

## Contributions

Contributions are welcome! Feel free to submit issues or pull requests to improve the tool or contribute implementations in additional languages.
