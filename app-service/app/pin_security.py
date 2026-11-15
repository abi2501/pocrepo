"""Compatible with edge/app/security.py; never log or persist plaintext PINs."""
import base64
import hashlib
import hmac
import secrets
import re

ALGORITHM = 'scrypt-n16384-r8-p1-dk32'
_PIN = re.compile(r'^[0-9]{6,12}$')


def make_verifier(pin: str) -> dict:
    if not isinstance(pin, str) or not _PIN.fullmatch(pin):
        raise ValueError('PIN must contain 6 to 12 decimal digits')
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(pin.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32)
    return {'algorithm': ALGORITHM, 'saltBase64': base64.b64encode(salt).decode('ascii'),
            'verifierBase64': base64.b64encode(digest).decode('ascii')}


def verify_pin(pin: str, record: dict) -> bool:
    if not isinstance(pin, str) or not _PIN.fullmatch(pin) or record.get('algorithm') != ALGORITHM:
        return False
    try:
        salt = base64.b64decode(record['saltBase64'], validate=True)
        expected = base64.b64decode(record['verifierBase64'], validate=True)
        if len(salt) != 16 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(pin.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(expected, actual)
    except (KeyError, ValueError, TypeError):
        return False
