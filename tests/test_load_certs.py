import pytest
from cryptography import x509

from host_key_signer.aws_iid_certificates import iid_certs


@pytest.mark.parametrize("key, value", [(k, v) for k, v in iid_certs.items()])
def test_load_cert(key, value):
    certificate = x509.load_pem_x509_certificate(value)
    assert certificate.serial_number
