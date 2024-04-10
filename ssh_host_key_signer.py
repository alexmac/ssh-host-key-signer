import base64
import os

import botocore.session

from host_key_signer.host_signature import ca_public_ssh_key, sign_ssh_host_key
from host_key_signer.instance_identity_doc import verify_instance_identity_document
from host_key_signer.kms import KMSEllipticCurvePrivateKey

KEY_ARN = os.environ["KEY_ARN"]
CERT_VALIDITY_HOURS = float(os.environ.get("CERT_VALIDITY_HOURS", 12.0))
DEBUG = os.environ.get("DEBUG", "false") == "true"


def handler(event, context):
    """
    Send this lambda a json payload containing:
        - an SSH host public key
        - a base64 encoded EC2 instance identity document
        - a base64 encoded RSA instance identity document signature

    It will respond with an SSH host key certificate signed by KMS
    See docs for more details on usage
    """
    try:
        host_pub_key = event["host_pub_key"]
        instance_identity_doc = base64.b64decode(event["instance_identity_doc"])
        instance_identity_doc_signature = base64.b64decode(
            event["instance_identity_doc_signature"]
        )

        iidoc = verify_instance_identity_document(
            signature=instance_identity_doc_signature,
            document=instance_identity_doc,
        )

        instance_id = iidoc["instanceId"]
        private_ip = iidoc["privateIp"]
        region = iidoc["region"]

        # This could be changed to support other hostnames
        private_ip_fqdn = f"ip-{private_ip.replace('.', '-')}.{region}.compute.internal"
        private_res_fqdn = f"{instance_id}.{region}.compute.internal"
        principals = [private_ip, private_ip_fqdn, private_res_fqdn, instance_id]

        session = botocore.session.get_session()
        kms_client = session.create_client("kms")

        private_key = KMSEllipticCurvePrivateKey(
            kms_client=kms_client,
            arn=KEY_ARN,
        )

        signed_host_key = sign_ssh_host_key(
            private_key,
            ssh_host_pub_key=host_pub_key,
            key_id=f"Host Key Cert for {instance_id} {region}",
            principals=principals,
            validity_hours=CERT_VALIDITY_HOURS,
        )

        public_key = ca_public_ssh_key(private_key).to_string()

        return {
            "statusCode": 200,
            "body": {
                "signed_host_key": signed_host_key,
                "authorized_hosts_line": f"@cert-authority * {public_key}",
                "validity_in_hours": CERT_VALIDITY_HOURS,
            },
        }
    except Exception:
        if DEBUG:
            raise
        return {
            "statusCode": 500,
            "body": {"error": "signing failed"},
        }


# import json
# print(handler(json.loads(open("test_payload.json").read()), None))
