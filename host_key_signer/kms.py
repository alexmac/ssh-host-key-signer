from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    KeySerializationEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_public_key,
)


class KMSEllipticCurvePublicKey(ec.EllipticCurvePublicKey):
    def __init__(self, der: bytes):
        self._der = der

    @property
    def curve(self) -> ec.EllipticCurve:
        public_key: ec.EllipticCurvePublicKey = load_der_public_key(
            data=self._der, backend=default_backend()
        )
        return public_key.curve

    @property
    def key_size(self) -> int:
        public_key: ec.EllipticCurvePublicKey = load_der_public_key(
            data=self._der, backend=default_backend()
        )
        return public_key.key_size

    def public_numbers(self) -> ec.EllipticCurvePublicNumbers:
        public_key: ec.EllipticCurvePublicKey = load_der_public_key(
            data=self._der, backend=default_backend()
        )
        return public_key.public_numbers()

    def public_bytes(
        self,
        encoding: Encoding,
        format: PublicFormat,
    ) -> bytes:
        if encoding == Encoding.DER:
            return self._der
        if encoding == Encoding.X962:
            public_key = load_der_public_key(data=self._der, backend=default_backend())

            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError(
                    "The provided DER bytes do not represent an elliptic curve public key."
                )

            return public_key.public_bytes(
                encoding=encoding,
                format=format,
            )
        raise NotImplementedError()

    def raw_bytes(self):
        return self._der

    def verify(
        self,
        signature: bytes,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> None:
        raise NotImplementedError()

    @classmethod
    def from_encoded_point(
        cls, curve: ec.EllipticCurve, data: bytes
    ) -> ec.EllipticCurvePublicKey:
        raise NotImplementedError()

    def __eq__(self, other: object) -> bool:
        raise NotImplementedError()


class KMSEllipticCurvePrivateKey(ec.EllipticCurvePrivateKey):
    def __init__(self, kms_client, arn: str):
        self._kms_client = kms_client
        self._arn = arn

    def exchange(
        self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        raise NotImplementedError()

    def public_key(self) -> KMSEllipticCurvePublicKey:
        response = self._kms_client.get_public_key(KeyId=self._arn)
        return KMSEllipticCurvePublicKey(der=response["PublicKey"])

    @property
    def curve(self) -> ec.EllipticCurve:
        raise NotImplementedError()

    @property
    def key_size(self) -> int:
        raise NotImplementedError()

    def sign(
        self,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        response = self._kms_client.sign(
            KeyId=self._arn,
            Message=data,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_384",
        )
        return response["Signature"]

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()
