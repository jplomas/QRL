import os
from unittest import TestCase

import simplejson as json
from click.testing import CliRunner
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.Wallet import Wallet, WalletDecryptionError
from qrl.cli import qrl as qrl_cli
from qrl.crypto.WebWalletV3 import decrypt_v3_envelope
from qrl.daemon.walletd import WalletD
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_qrl_dir


def web_envelope(payload, password):
    salt = os.urandom(32)
    iv = os.urandom(12)
    kdf = {'name': 'scrypt', 'params': {
        'N': 1 << 17, 'r': 8, 'p': 1, 'dkLen': 32, 'salt': salt.hex()}}
    cipher = {'name': 'aes-256-gcm', 'iv': iv.hex()}
    aad = json.dumps({'version': 3, 'kdf': kdf, 'cipher': cipher}, separators=(',', ':')).encode()
    key = Scrypt(salt=salt, length=32, n=1 << 17, r=8, p=1).derive(password.encode())
    plaintext = json.dumps(payload, separators=(',', ':')).encode()
    sealed = AESGCM(key).encrypt(iv, plaintext, aad)
    cipher['authTag'] = sealed[-16:].hex()
    return {'version': 3, 'encrypted': True, 'kdf': kdf,
            'cipher': cipher, 'data': sealed[:-16].hex()}


class TestWebWalletV3(TestCase):
    def test_rejects_unbounded_or_tampered_v3_metadata(self):
        envelope = web_envelope({'address': 'example'}, 'password')
        envelope['kdf']['params']['N'] = 1 << 21
        envelope['kdf']['params']['r'] = 32
        with self.assertRaises(ValueError):
            decrypt_v3_envelope(envelope, 'password')

        envelope = web_envelope({'address': 'example'}, 'password')
        envelope['cipher']['iv'] = ('0' if envelope['cipher']['iv'][0] != '0' else '1') + envelope['cipher']['iv'][1:]
        with self.assertRaises(ValueError):
            decrypt_v3_envelope(envelope, 'password')

    def test_cli_wallet_imports_web_v3_without_exposing_plaintext_on_failed_unlock(self):
        with set_qrl_dir('wallet_ver1'):
            source = Wallet()
            with open(source.wallet_path) as wallet_file:
                record = json.load(wallet_file)['addresses'][0]
            record['pk'] = bin2hstr(source.get_xmss_by_index(0).pk)
            envelope = web_envelope(record, 'password')
            with open(source.wallet_path, 'w') as wallet_file:
                json.dump(envelope, wallet_file)

            imported = Wallet()
            self.assertTrue(imported.encrypted)
            self.assertEqual(imported.address_items, [])
            cli = CliRunner()
            wallet_dir = os.path.dirname(source.wallet_path)
            secret = cli.invoke(qrl_cli, ['--wallet_dir', wallet_dir, 'wallet_secret',
                                          '--wallet-idx', '0'], input='password\n')
            self.assertEqual(secret.exit_code, 0, secret.output)
            self.assertIn(record['mnemonic'], secret.output)
            generation = cli.invoke(qrl_cli, ['--wallet_dir', wallet_dir, 'wallet_gen', '--height', '4'])
            self.assertIn('Wallet already exists', generation.output)
            with self.assertRaises(WalletDecryptionError):
                imported.decrypt('wrong')
            self.assertTrue(imported.encrypted)
            self.assertEqual(imported.get_xmss_by_index(0, 'password').qaddress, record['address'])
            self.assertTrue(imported.encrypted)

            imported.decrypt('password')
            self.assertEqual(imported.address_items[0].qaddress, record['address'])
            imported.encrypt('password')
            imported.save()
            reloaded = Wallet()
            self.assertEqual(reloaded._encryption_version, 2)
            reloaded.decrypt('password')
            self.assertEqual(reloaded.address_items[0].qaddress, record['address'])

    def test_cli_wallet_imports_unencrypted_web_v3(self):
        with set_qrl_dir('wallet_ver1'):
            source = Wallet()
            with open(source.wallet_path) as wallet_file:
                record = json.load(wallet_file)['addresses'][0]
            with open(source.wallet_path, 'w') as wallet_file:
                json.dump({'version': 3, 'encrypted': False, 'data': record}, wallet_file)
            imported = Wallet()
            self.assertFalse(imported.encrypted)
            self.assertEqual(imported.get_xmss_by_index(0).qaddress, record['address'])

    def test_cli_removes_from_imported_web_v3_without_plaintext_write(self):
        with set_qrl_dir('wallet_ver1'):
            source = Wallet()
            source.add_new_address(height=4)
            source.save()
            with open(source.wallet_path) as wallet_file:
                records = json.load(wallet_file)['addresses']
            with open(source.wallet_path, 'w') as wallet_file:
                json.dump(web_envelope(records, 'password'), wallet_file)

            result = CliRunner().invoke(qrl_cli, ['--wallet_dir', os.path.dirname(source.wallet_path),
                                                  'wallet_rm', '--wallet-idx', '0',
                                                  '--skip-confirmation'], input='password\n')
            self.assertEqual(result.exit_code, 0, result.output)
            with open(source.wallet_path) as wallet_file:
                saved = json.load(wallet_file)
            self.assertTrue(saved['encrypted'])
            self.assertEqual(saved['encryption_version'], 2)
            self.assertEqual(len(saved['addresses']), 1)
            self.assertEqual(saved['addresses'][0]['address'], records[1]['address'])

    def test_cli_recovers_into_imported_web_v3_without_plaintext_write(self):
        with set_qrl_dir('wallet_ver1'):
            source = Wallet()
            with open(source.wallet_path) as wallet_file:
                record = json.load(wallet_file)['addresses'][0]
            recovered = source.add_new_address(height=4)
            with open(source.wallet_path, 'w') as wallet_file:
                json.dump(web_envelope(record, 'password'), wallet_file)

            result = CliRunner().invoke(qrl_cli, ['--wallet_dir', os.path.dirname(source.wallet_path),
                                                  'wallet_recover', '--seed-type', 'hexseed'],
                                        input='{}\npassword\ny\n'.format(recovered.hexseed))
            self.assertEqual(result.exit_code, 0, result.output)
            with open(source.wallet_path) as wallet_file:
                saved = json.load(wallet_file)
            self.assertTrue(saved['encrypted'])
            self.assertEqual(saved['encryption_version'], 2)
            self.assertEqual(len(saved['addresses']), 2)

    def test_walletd_imports_web_v3_and_preserves_slaves(self):
        with set_qrl_dir('wallet_ver1'):
            walletd = WalletD()
            walletd._wallet.append_xmss(get_alice_xmss())
            walletd._wallet.append_slave([get_bob_xmss()], None, index=0)
            walletd._wallet.save()
            with open(walletd._wallet_path) as wallet_file:
                payload = json.load(wallet_file)
            payload['encrypted'] = False
            slave_address = payload['addresses'][0]['slaves'][0][0]['address']
            envelope = web_envelope(payload, 'password')
            with open(walletd._wallet_path, 'w') as wallet_file:
                json.dump(envelope, wallet_file)

            walletd.load_wallet()
            self.assertTrue(walletd._wallet.encrypted)
            self.assertTrue(walletd._wallet.needs_encryption_migration())
            with self.assertRaises(Exception):
                walletd.unlock_wallet('wrong')
            with open(walletd._wallet_path) as wallet_file:
                self.assertEqual(json.load(wallet_file), envelope)

            walletd.unlock_wallet('password')
            self.assertEqual(walletd._wallet.address_items[0].slaves[0][0].qaddress, slave_address)
            with open(walletd._wallet_path) as wallet_file:
                self.assertEqual(json.load(wallet_file)['encryption_version'], 2)
            walletd.load_wallet()
            walletd.unlock_wallet('password')
            self.assertEqual(walletd._wallet.address_items[0].slaves[0][0].qaddress, slave_address)
