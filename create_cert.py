import base64
import datetime
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from constants import Permissions, private_key


def issue_spkison(
    subject_public_key_pem, permissions: list[Permissions], subject_name, subject_id
):
    cert = {
        "type": "SPKISON",
        "version": "1",
        "issuer": "SPKISON Authority",
        "issuer_id": "SPKISON Authority 123",
        "subject_name": subject_name,
        "subject_id": subject_id,
        "subject_key": subject_public_key_pem,
        "algorithm": "RSA",
        "validity": {
            "not_before": datetime.datetime.utcnow().isoformat() + "Z",
            "not_after": (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
            + "Z",
        },
        "extensions": {"permissions": [permission.to_dict() for permission in permissions]},
    }

    cert_bytes = json.dumps(cert, sort_keys=True).encode()
    signature = private_key.sign(cert_bytes, padding.PKCS1v15(), hashes.SHA256())

    cert["signature"] = base64.b64encode(signature).decode()

    return cert
