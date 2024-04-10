import json
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from host_key_signer.aws_iid_certificates import iid_certs, iid_region_to_cert


def verify_instance_identity_document(signature: bytes, document: bytes) -> dict:
    doc_hash = sha256(document).digest()

    untrusted_doc = json.loads(document.decode())

    public_key_pem = iid_certs[iid_region_to_cert[untrusted_doc["region"]]]

    certificate = x509.load_pem_x509_certificate(public_key_pem)

    certificate.public_key().verify(
        signature,
        doc_hash,
        padding.PKCS1v15(),
        Prehashed(hashes.SHA256()),
    )
    return untrusted_doc
