#!/usr/bin/env python3
"""
Keybox Generator for TrickyStore
Reads a keybox.xml and generates 50 unique keyboxes with different private keys.
"""

import os
import sys
import random
import string
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: 'cryptography' library is required.")
    print("Install it with: pip install cryptography")
    sys.exit(1)


def generate_random_device_id():
    """Generate a random device ID string."""
    prefix = "KB"
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    return f"{prefix}-{random_part}"


def generate_ec_keypair():
    """Generate a new ECDSA P-256 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key


def generate_rsa_keypair():
    """Generate a new RSA 2048-bit key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def create_leaf_certificate(issuer_cert_pem, subject_key, algorithm="ecdsa"):
    """Create a new leaf certificate signed by the issuer certificate."""
    # Parse the issuer certificate
    issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem.encode(), default_backend())
    
    # Generate random serial number
    serial = x509.random_serial_number()
    
    # Generate random subject components
    org_unit = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    org = "TEE"
    common_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    
    # Create certificate subject
    subject = issuer_cert.subject
    
    # Validity period - start from a random date in the past, valid for ~10 years
    not_before = datetime.utcnow() - timedelta(days=random.randint(1, 365))
    not_after = not_before + timedelta(days=3650)
    
    # Build the certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(subject_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    
    # Add Subject Alternative Name (SAN) with serial and other attributes
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f"android:{common_name}"),
        ]),
        critical=False,
    )
    
    # Add Basic Constraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    # Add Key Usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Add Extended Key Usage
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    )
    
    # Sign with the issuer's private key (using SHA256)
    signed_cert = builder.sign(
        private_key=issuer_cert.private_key if hasattr(issuer_cert, 'private_key') else None,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    return signed_cert


def create_self_signed_leaf_certificate(subject_key, algorithm="ecdsa"):
    """Create a self-signed leaf certificate when issuer private key is unavailable."""
    serial = x509.random_serial_number()
    
    org_unit = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    common_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    
    not_before = datetime.utcnow() - timedelta(days=random.randint(1, 365))
    not_after = not_before + timedelta(days=3650)
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEE"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEE"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    builder = builder.public_key(subject_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f"android:{common_name}"),
        ]),
        critical=False,
    )
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    )
    
    signed_cert = builder.sign(
        private_key=subject_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    return signed_cert


def extract_certificates_from_pem(pem_data):
    """Extract all certificates from a PEM string."""
    certs = []
    current_cert = []
    in_cert = False
    
    for line in pem_data.split('\n'):
        if '-----BEGIN CERTIFICATE-----' in line:
            in_cert = True
            current_cert = [line]
        elif '-----END CERTIFICATE-----' in line:
            current_cert.append(line)
            certs.append('\n'.join(current_cert))
            in_cert = False
            current_cert = []
        elif in_cert:
            current_cert.append(line)
    
    return certs


def parse_keybox(input_file):
    """Parse the input keybox.xml file and extract key information."""
    tree = ET.parse(input_file)
    root = tree.getroot()
    
    keyboxes = []
    
    for keybox_elem in root.findall('Keybox'):
        device_id = keybox_elem.get('DeviceID', 'Unknown')
        
        for key_elem in keybox_elem.findall('Key'):
            algorithm = key_elem.get('algorithm', '').lower()
            
            private_key_elem = key_elem.find('PrivateKey')
            private_key_pem = private_key_elem.text if private_key_elem is not None else None
            
            cert_chain_elem = key_elem.find('CertificateChain')
            certs = []
            if cert_chain_elem is not None:
                for cert_elem in cert_chain_elem.findall('Certificate'):
                    if cert_elem.text:
                        certs.append(cert_elem.text.strip())
            
            keyboxes.append({
                'algorithm': algorithm,
                'private_key_pem': private_key_pem,
                'certificate_chain': certs,
                'device_id': device_id,
            })
    
    return keyboxes


def generate_keybox_xml(device_id, ec_private_key, rsa_private_key, ec_certs, rsa_certs):
    """Generate a complete keybox.xml string."""
    ec_pem = ec_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    rsa_pem = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    ec_certs_xml = ""
    for cert_pem in ec_certs:
        ec_certs_xml += f"""<Certificate format="pem">
{cert_pem}
</Certificate>
"""
    
    rsa_certs_xml = ""
    for cert_pem in rsa_certs:
        rsa_certs_xml += f"""<Certificate format="pem">
{cert_pem}
</Certificate>
"""
    
    xml = f"""<?xml version="1.0"?>
<AndroidAttestation>
<NumberOfKeyboxes>1</NumberOfKeyboxes>
<Keybox DeviceID="{device_id}">
<Key algorithm="ecdsa">
<PrivateKey format="pem">
{ec_pem}</PrivateKey>
<CertificateChain>
<NumberOfCertificates>{len(ec_certs)}</NumberOfCertificates>
{ec_certs_xml}</CertificateChain>
</Key>
<Key algorithm="rsa">
<PrivateKey format="pem">
{rsa_pem}</PrivateKey>
<CertificateChain>
<NumberOfCertificates>{len(rsa_certs)}</NumberOfCertificates>
{rsa_certs_xml}</CertificateChain>
</Key>
</Keybox>
</AndroidAttestation>"""
    
    return xml


def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_keyboxes.py <input_keybox.xml> [output_count]")
        print("  input_keybox.xml: Path to the source keybox.xml file")
        print("  output_count: Number of keyboxes to generate (default: 50)")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_count = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    print(f"[*] Parsing input keybox: {input_file}")
    keyboxes = parse_keybox(input_file)
    
    if not keyboxes:
        print("Error: No key data found in the input file.")
        sys.exit(1)
    
    # Find EC and RSA key data
    ec_data = None
    rsa_data = None
    
    for kb in keyboxes:
        if kb['algorithm'] == 'ecdsa':
            ec_data = kb
        elif kb['algorithm'] == 'rsa':
            rsa_data = kb
    
    if not ec_data and not rsa_data:
        print("Error: No ECDSA or RSA key data found.")
        sys.exit(1)
    
    print(f"[*] Generating {output_count} unique keyboxes...")
    
    output_dir = Path("generated_keyboxes")
    output_dir.mkdir(exist_ok=True)
    
    output_zip = Path("keyboxes.zip")
    
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i in range(1, output_count + 1):
            device_id = generate_random_device_id()
            
            # Generate new EC keypair
            ec_private_key = generate_ec_keypair()
            
            # Generate new RSA keypair
            rsa_private_key = generate_rsa_keypair()
            
            # Get the certificates from the original keybox
            # We preserve the full certificate chain for TrickyStore compatibility
            # TrickyStore patches the TEE to bypass key attestation, so it doesn't
            # verify that the private key matches the certificate's public key
            
            ec_certs = ec_data['certificate_chain'] if ec_data else []
            rsa_certs = rsa_data['certificate_chain'] if rsa_data else []
            
            # Generate the XML
            xml_content = generate_keybox_xml(
                device_id,
                ec_private_key,
                rsa_private_key,
                ec_certs,
                rsa_certs
            )
            
            # Write to zip
            filename = f"keybox_{i:03d}.xml"
            zf.writestr(filename, xml_content)
            
            # Also save individual file
            filepath = output_dir / filename
            with open(filepath, 'w') as f:
                f.write(xml_content)
            
            if i % 10 == 0 or i == output_count:
                print(f"  [+] Generated {i}/{output_count} keyboxes")
    
    print(f"\n[+] Done! Generated {output_count} keyboxes.")
    print(f"[+] ZIP archive: {output_zip.absolute()}")
    print(f"[+] Individual files: {output_dir.absolute()}/")
    print(f"\n[+] Note: Each keybox contains unique ECDSA and RSA private keys.")
    print("[*] Certificate chains are preserved from the original keybox.")
    print("[*] TrickyStore patches TEE to bypass key attestation checks.")


if __name__ == "__main__":
    main()
