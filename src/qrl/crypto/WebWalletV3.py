import simplejson
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def is_v3_envelope(value):
    return (isinstance(value, dict) and value.get('version') == 3 and
            type(value.get('encrypted')) is bool and 'data' in value)


def wallet_records(payload):
    if isinstance(payload, dict) and 'addresses' in payload:
        if payload.get('encrypted') is not False:
            raise ValueError('Encrypted fields inside a web wallet envelope')
        records = payload['addresses']
    elif isinstance(payload, dict):
        records = [payload]
    else:
        records = payload
    if not isinstance(records, list) or not records or not all(isinstance(item, dict) for item in records):
        raise ValueError('Invalid web wallet records')
    if any(item.get('encrypted') is True for item in records):
        raise ValueError('Encrypted fields inside a web wallet envelope')
    return records


def _hex_bytes(value, length=None):
    if not isinstance(value, str) or len(value) % 2:
        raise ValueError('Invalid web wallet hex value')
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('Invalid web wallet hex value') from error
    if not result or (length is not None and len(result) != length):
        raise ValueError('Invalid web wallet hex value')
    return result


def _kdf_params(kdf):
    if not isinstance(kdf, dict) or kdf.get('name') != 'scrypt' or not isinstance(kdf.get('params'), dict):
        raise ValueError('Unsupported web wallet KDF')
    params = kdf['params']
    n, r, p, length = (params.get(name) for name in ('N', 'r', 'p', 'dkLen'))
    if (type(n) is not int or n < 1024 or n > 1 << 21 or n & (n - 1) or
            type(r) is not int or r < 1 or r > 32 or
            type(p) is not int or p < 1 or p > 4 or
            length != 32 or type(length) is not int or
            128 * n * r > 512 * 1024 * 1024):
        raise ValueError('Unsupported web wallet KDF parameters')
    return n, r, p, _hex_bytes(params.get('salt'))


def decrypt_v3_envelope(envelope, passphrase):
    if not is_v3_envelope(envelope):
        raise ValueError('Invalid web wallet envelope')
    if not envelope['encrypted']:
        payload = envelope['data']
        return simplejson.loads(payload) if isinstance(payload, str) else payload
    if not passphrase:
        raise ValueError('Missing web wallet passphrase')

    n, r, p, salt = _kdf_params(envelope.get('kdf'))
    cipher = envelope.get('cipher')
    if not isinstance(cipher, dict) or cipher.get('name') != 'aes-256-gcm':
        raise ValueError('Unsupported web wallet cipher')
    iv = _hex_bytes(cipher.get('iv'), 12)
    tag = _hex_bytes(cipher.get('authTag'), 16)
    ciphertext = _hex_bytes(envelope['data'])
    aad = simplejson.dumps({
        'version': 3,
        'kdf': envelope['kdf'],
        'cipher': {'name': cipher['name'], 'iv': cipher['iv']},
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    key = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode('utf-8'))
    try:
        plaintext = AESGCM(key).decrypt(iv, ciphertext + tag, aad)
    except InvalidTag as error:
        raise ValueError('Web wallet passphrase is incorrect or file is corrupt') from error
    return simplejson.loads(plaintext)
