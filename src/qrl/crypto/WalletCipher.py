import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from qrl.crypto.AESHelper import AESHelper


PREFIX = 'qrl-node-v2'
SALT_LENGTH = 32
NONCE_LENGTH = 12
TAG_LENGTH = 16
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1


def wallet_field_aad(qaddress, field):
    return ('{}:{}:{}'.format(PREFIX, qaddress, field)).encode('ascii')


class WalletCipher:
    @staticmethod
    def is_versioned(ciphertext):
        return isinstance(ciphertext, str) and ciphertext.startswith(PREFIX + ':')

    def __init__(self, passphrase, allow_legacy=True):
        self._passphrase = passphrase
        self._allow_legacy = allow_legacy
        self._salt = None
        self._key = None

    def _key_for_salt(self, salt):
        if salt != self._salt or self._key is None:
            self._key = Scrypt(salt=salt, length=32, n=SCRYPT_N,
                               r=SCRYPT_R, p=SCRYPT_P).derive(self._passphrase.encode('utf-8'))
            self._salt = salt
        return self._key

    def encrypt(self, plaintext, aad):
        salt = self._salt if self._salt is not None else os.urandom(SALT_LENGTH)
        key = self._key_for_salt(salt)
        nonce = os.urandom(NONCE_LENGTH)
        sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
        return '{}:{}:{}:{}:{}'.format(PREFIX, salt.hex(), nonce.hex(),
                                       sealed[-TAG_LENGTH:].hex(), sealed[:-TAG_LENGTH].hex())

    def decrypt(self, ciphertext, aad):
        if not isinstance(ciphertext, str):
            raise ValueError('Invalid wallet ciphertext')
        if ciphertext.startswith(PREFIX + ':'):
            parts = ciphertext.split(':')
            if len(parts) != 5 or any(not part or len(part) % 2 for part in parts[1:]):
                raise ValueError('Invalid wallet ciphertext envelope')
            try:
                salt, nonce, tag, data = (bytes.fromhex(part) for part in parts[1:])
            except ValueError as error:
                raise ValueError('Invalid wallet ciphertext envelope') from error
            if len(salt) != SALT_LENGTH or len(nonce) != NONCE_LENGTH or len(tag) != TAG_LENGTH:
                raise ValueError('Invalid wallet ciphertext envelope')
            return AESGCM(self._key_for_salt(salt)).decrypt(nonce, data + tag, aad)
        if ':' in ciphertext:
            raise ValueError('Unsupported wallet ciphertext envelope')
        if not self._allow_legacy:
            raise ValueError('Legacy ciphertext in a versioned wallet')
        return AESHelper(self._passphrase).decrypt(ciphertext)
