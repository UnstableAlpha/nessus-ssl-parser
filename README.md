# Nessus SSL/TLS Vulnerability Parser

## Overview

A Python script that parses Nessus vulnerability scan results (`.nessus` files) to identify hosts affected by SSL/TLS-related issues. The script generates a list of affected hosts and provides guidance for further testing using `testssl.sh`.

## Features

The script identifies hosts affected by common SSL/TLS vulnerabilities, including:

* Certificate validity and trust issues
* Weak cipher suites
* Protocol version vulnerabilities (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
* Known vulnerabilities (POODLE, FREAK, Logjam)
* Certificate chain issues
* Hashing algorithm weaknesses

## Requirements

* Python 3.7 or higher
* No external dependencies required (uses standard library only)

## Installation

Clone this repository to your local machine:

```bash
git clone https://github.com/yourusername/nessus-ssl-parser.git
cd nessus-ssl-parser
```

## Usage

Run the script with two arguments: the input `.nessus` file and the desired output file name:

```bash
python nessus_ssl_parser.py input.nessus output.txt
```

### Script Operation

The script performs the following operations:

1. Parses the `.nessus` file for SSL/TLS-related findings
2. Generates a list of unique affected hosts in the format `<ipAddress>:<port>`
3. Saves the results to the specified output file
4. Displays a command for running further SSL/TLS testing using `testssl.sh`

### Example Output

```plaintext
Found 25 unique vulnerable hosts. Results written to output.txt

Run testssl.sh against the identified hosts using the following command:
testssl.sh -iL output.txt --parallel --csv --html
```

## Covered Nessus Plugin IDs

The script checks for the following Nessus plugin IDs:

| Plugin ID | Description |
|-----------|-------------|
| 15901 | SSL Certificate Expiry |
| 20007 | SSL Version 2 and 3 Protocol Detection |
| 31705 | SSL Weak Cipher Suites Supported |
| 35291 | SSL Certificate Signed Using Weak Hashing Algorithm |
| 42873 | SSL Medium Strength Cipher Suites Supported |
| 45411 | SSL Certificate with Wrong Hostname |
| 51192 | SSL Certificate Cannot Be Trusted |
| 57582 | SSL Self-Signed Certificate |
| 60108 | SSL Certificate Chain Contains Certificates from Multiple Organizations |
| 60119 | SSL Certificate Chain Contains Unnecessary Certificates |
| 62565 | TLS Version 1.0 Protocol Detection |
| 65821 | SSL RC4 Cipher Suites Supported |
| 69551 | SSL Certificate Chain Contains RSA Keys Less Than 2048 bits |
| 70544 | SSL Forward Secrecy Not Supported |
| 73404 | SSL Certificate Expires Soon |
| 78479 | SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE) |
| 83875 | SSL Certificate Signed Using SHA-1 Algorithm |
| 84089 | SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam) |
| 90317 | SSH Weak Algorithms Supported |
| 91572 | SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK) |
| 95715 | SSL/TLS Versions Supported |
| 104743 | TLS Version 1.1 Protocol Enabled |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

James Burns

## Acknowledgments

* Initial project requirements and specifications provided by James Burns at Silvatech
* Inspired by the need to streamline SSL/TLS vulnerability assessment workflows

---

**Note**: This tool is intended for use by security professionals during authorised security assessments. Always ensure you have appropriate permission before conducting security testing.
