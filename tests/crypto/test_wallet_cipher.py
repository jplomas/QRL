from unittest import TestCase

from cryptography.exceptions import InvalidTag

from qrl.crypto.AESHelper import AESHelper
from qrl.crypto.WalletCipher import WalletCipher, wallet_field_aad


class TestWalletCipher(TestCase):
    def test_new_ciphertext_round_trip_and_context_binding(self):
        aad = wallet_field_aad('Qaddress', 'hexseed')
        cipher = WalletCipher('passphrase')
        encrypted = cipher.encrypt(b'secret seed', aad)

        self.assertTrue(encrypted.startswith('qrl-node-v2:'))
        self.assertEqual(b'secret seed', WalletCipher('passphrase').decrypt(encrypted, aad))
        with self.assertRaises(InvalidTag):
            WalletCipher('wrong').decrypt(encrypted, aad)
        with self.assertRaises(InvalidTag):
            WalletCipher('passphrase').decrypt(
                encrypted, wallet_field_aad('Qaddress', 'mnemonic'))

    def test_tampering_fails_authentication(self):
        aad = wallet_field_aad('Qaddress', 'mnemonic')
        encrypted = WalletCipher('passphrase').encrypt(b'mnemonic words', aad)
        parts = encrypted.split(':')
        parts[-1] = ('0' if parts[-1][0] != '0' else '1') + parts[-1][1:]

        with self.assertRaises(InvalidTag):
            WalletCipher('passphrase').decrypt(':'.join(parts), aad)
        with self.assertRaises(ValueError):
            WalletCipher('passphrase').decrypt('qrl-node-v9:' + ':'.join(parts[1:]), aad)

    def test_legacy_ciphertext_is_still_readable(self):
        encrypted = AESHelper('passphrase').encrypt(b'old seed')
        self.assertEqual(b'old seed', WalletCipher('passphrase').decrypt(
            encrypted, wallet_field_aad('Qaddress', 'hexseed')))
