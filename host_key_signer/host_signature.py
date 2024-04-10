from datetime import datetime, timedelta, timezone
from typing import List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from sshkey_tools.cert import CertificateFields, Ed25519Certificate, SSHCertificate
from sshkey_tools.fields import (
    CERT_TYPE,
    CertificateTypeField,
    KeyIdField,
    PrincipalsField,
    SerialField,
    ValidAfterField,
    ValidBeforeField,
)
from sshkey_tools.keys import (
    EcdsaCurves,
    EcdsaPrivateKey,
    EcdsaPublicKey,
    Ed25519PublicKey,
)

from host_key_signer.kms import KMSEllipticCurvePrivateKey


def ca_public_ssh_key(ca_private_key: KMSEllipticCurvePrivateKey) -> EcdsaPublicKey:
    pub = load_der_public_key(
        data=ca_private_key.public_key()._der, backend=default_backend()
    )
    return EcdsaPublicKey(pub)


def sign_ssh_host_key(
    ca_privkey: KMSEllipticCurvePrivateKey,
    ssh_host_pub_key: str,
    key_id: str,
    principals: List[str],
    validity_hours: float,
) -> str:
    now = datetime.now(timezone.utc)

    subject_pubkey = Ed25519PublicKey.from_string(ssh_host_pub_key)

    cert_fields = CertificateFields(
        serial=SerialField(0),
        cert_type=CertificateTypeField(CERT_TYPE.HOST),
        key_id=KeyIdField(key_id),
        principals=PrincipalsField(principals),
        valid_after=ValidAfterField(now),
        valid_before=ValidBeforeField(now + timedelta(hours=validity_hours)),
    )

    certificate = Ed25519Certificate(
        subject_pubkey=subject_pubkey,
        ca_privkey=EcdsaPrivateKey.generate(
            curve=EcdsaCurves.P384
        ),  # Not really used, just abusing the API here
        fields=cert_fields,
    )

    # Sign via KMS - hacky abuse of the sshkey_tools api
    certificate.footer.ca_pubkey = ca_public_ssh_key(ca_privkey)
    certificate.footer.signature.value = ca_privkey.sign(
        certificate.get_signable(), None
    )
    certificate.footer.signature.is_signed = True

    # Confirm the cert is signed properly
    testcert = SSHCertificate.from_string(certificate.to_string())
    testcert.verify()

    return certificate.to_string()
