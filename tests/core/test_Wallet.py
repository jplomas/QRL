# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os
import stat
from unittest import TestCase

import simplejson as json
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.Wallet import Wallet, WalletEncryptionError, WalletVersionError, WalletDecryptionError
from qrl.core import config
from qrl.core.misc import logger
from qrl.crypto.AESHelper import AESHelper
from tests.misc.helper import set_qrl_dir

logger.initialize_default()


class TestWalletVer0(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWalletVer0, self).__init__(*args, **kwargs)

    def test_init(self):
        with set_qrl_dir("wallet_ver0"):
            wallet = Wallet()
            self.assertIsNotNone(wallet)

    def test_read_ver0(self):
        with set_qrl_dir("wallet_ver0"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))
            self.assertEqual(wallet.version, 0)

            addr_item = wallet.address_items[0]
            self.assertFalse(addr_item.encrypted)

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_read_secure_ver0(self):
        with set_qrl_dir("wallet_secure_ver0"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))
            self.assertEqual(wallet.version, 0)

            self.assertTrue(wallet.address_items[0].encrypted)

            wallet.decrypt_item_ver0(0, 'test1234')
            addr_item = wallet.address_items[0]

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_read_wallet_ver0_saves_wallet_ver1(self):
        with set_qrl_dir("wallet_ver0"):
            wallet = Wallet()
            self.assertEqual(wallet.version, 0)

            wallet.version = 1
            wallet.save()

            wallet_reloaded = Wallet()
            self.assertEqual(wallet_reloaded.version, 1)

    def test_decrypt_ver0_then_save_without_manual_version_bump(self):
        # github.com/theQRL/QRL#1592: `qrl wallet_decrypt` on a ver0 wallet
        # decrypts fine but save() then rejected it as "still version 0".
        # decrypt() must migrate the version marker on its own.
        with set_qrl_dir("wallet_secure_ver0"):
            wallet = Wallet()
            self.assertEqual(wallet.version, 0)

            wallet.decrypt('test1234')
            self.assertEqual(wallet.version, 1)

            wallet.save()

            wallet_reloaded = Wallet()
            self.assertEqual(wallet_reloaded.version, 1)
            self.assertFalse(wallet_reloaded.encrypted)
            self.assertEqual(wallet_reloaded.address_items[0].qaddress,
                             'Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f')

    def test_read_wallet_secure_ver0_saves_wallet_ver1_encrypted(self):
        with set_qrl_dir("wallet_secure_ver0"):
            wallet = Wallet()

            self.assertEqual(wallet.version, 0)

            # Wallet will not let you save an encrypted ver0 wallet as ver1. You have to decrypt it first.
            # This is because Qaddress is unencrypted in the ver1 wallet.
            with self.assertRaises(WalletVersionError):
                wallet.save()

            wallet.decrypt('test1234')
            wallet.encrypt('test1234')
            wallet.version = 1
            wallet.save()

            wallet_reloaded = Wallet()
            self.assertEqual(wallet_reloaded.version, 1)

            self.assertEqual(wallet_reloaded.address_items[0].qaddress,
                             'Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f')

            wallet_reloaded.decrypt('test1234')
            addr_item = wallet_reloaded.address_items[0]

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            xmss0 = wallet_reloaded.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet_reloaded.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))


class TestWallet(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWallet, self).__init__(*args, **kwargs)

    def test_read(self):
        with set_qrl_dir("wallet_ver1"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))
            self.assertEqual(wallet.version, 1)

            addr_item = wallet.address_items[0]
            self.assertFalse(addr_item.encrypted)

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_existing_wallet_file_is_private_on_load(self):
        with set_qrl_dir("wallet_ver1"):
            path = os.path.join(config.user.wallet_dir, config.dev.wallet_dat_filename)
            os.chmod(config.user.wallet_dir, 0o755)
            os.chmod(path, 0o644)
            Wallet()
            self.assertEqual(stat.S_IMODE(os.stat(config.user.wallet_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_removed_address_does_not_leave_cached_index(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            first = wallet.add_new_address(height=4)
            second = wallet.add_new_address(height=4)
            wallet.get_xmss_by_index(0)
            wallet.get_xmss_by_index(1)
            self.assertTrue(wallet.remove(first.qaddress))
            self.assertEqual(wallet.get_xmss_by_index(0).qaddress, second.qaddress)

    def test_read_secure(self):
        with set_qrl_dir("wallet_secure_ver1"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))
            self.assertEqual(wallet.version, 1)
            self.assertTrue(wallet.encrypted)

            addr_item = wallet.address_items[0]

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            wallet.decrypt_item(0, 'test1234')
            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_create(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            self.assertEqual(0, len(wallet.address_items))

            xmss1 = wallet.add_new_address(4)
            self.assertEqual(1, len(wallet.address_items))

            xmss2 = wallet.get_xmss_by_index(0)

            self.assertEqual(xmss1.address, xmss2.address)
            self.assertEqual(xmss1.mnemonic, xmss2.mnemonic)

    def test_create_load(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.save()

            wallet_b = Wallet()
            self.assertEqual(1, len(wallet_b.address_items))

            self.assertEqual(wallet.address_items[0], wallet_b.address_items[0])

    def test_create_custom_hash_function(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            xmss = wallet.add_new_address(height=4, hash_function="sha2_256")
            self.assertEqual("sha2_256", xmss.hash_function)

    def test_create_custom_hash_function_load(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            xmss = wallet.add_new_address(height=4, hash_function="sha2_256")
            wallet.save()

            self.assertEqual("sha2_256", xmss.hash_function)

            wallet_reloaded = Wallet()
            self.assertEqual("sha2_256", wallet_reloaded.address_items[0].hashFunction)

    def test_integrity_behaviour(self):
        with set_qrl_dir("no_data"):
            TEST_KEY = 'mytestkey'
            wallet = Wallet()
            wallet.add_new_address(4)
            wallet.add_new_address(4)
            wallet.encrypt(TEST_KEY)

            # An encrypted wallet is not editable.
            with self.assertRaises(WalletEncryptionError):
                wallet.add_new_address(4)
            # You may not re-encrypt it.
            with self.assertRaises(WalletEncryptionError):
                wallet.encrypt(TEST_KEY)
            # You can save it.
            wallet.save()

            wallet.decrypt_item(1, TEST_KEY)
            # A partially encrypted wallet is not editable.
            with self.assertRaises(WalletEncryptionError):
                wallet.add_new_address(4)
            # You may not re-encrypt it.
            with self.assertRaises(WalletEncryptionError):
                wallet.encrypt(TEST_KEY)
            # You may not re-decrypt it.
            with self.assertRaises(WalletEncryptionError):
                wallet.decrypt(TEST_KEY)
            # You can't even save it.
            with self.assertRaises(WalletEncryptionError):
                wallet.save()

            wallet.decrypt_item(0, TEST_KEY)
            # A fully decrypted wallet is editable.
            wallet.add_new_address(4)
            # You may not re-decrypt it.
            with self.assertRaises(WalletEncryptionError):
                wallet.decrypt(TEST_KEY)
            # You can save it.
            wallet.save()

    def test_encrypt_wallet(self):
        # 2 unencrypted addresses. This should work.
        with set_qrl_dir("no_data"):
            TEST_KEY = 'mytestkey'
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.add_new_address(height=4)

            wallet.encrypt(TEST_KEY)

            self.assertTrue(wallet.encrypted)
            self.assertFalse(wallet.encrypted_partially)

    def test_decrypt_wallet(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.add_new_address(height=4)
            addresses = wallet.addresses

            TEST_KEY = 'mytestkey'
            wallet.encrypt(TEST_KEY)
            self.assertTrue(wallet.encrypted)

            wallet.decrypt(TEST_KEY)
            self.assertEqual(addresses, wallet.addresses)
            self.assertFalse(wallet.encrypted_partially)

    def test_decrypt_wallet_wrong(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.add_new_address(height=4)
            addresses = wallet.addresses

            TEST_KEY = 'mytestkey'
            wallet.encrypt(TEST_KEY)
            self.assertTrue(wallet.encrypted)

            TEST_KEY = 'mytestkey_is_wrong'
            with self.assertRaises(WalletDecryptionError):
                wallet.decrypt(TEST_KEY)
            self.assertEqual(addresses, wallet.addresses)
            self.assertFalse(wallet.encrypted_partially)

    def test_encrypt_save_reload(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.save()

            wallet_b = Wallet()

            self.assertEqual(1, len(wallet_b.address_items))
            self.assertEqual(wallet.address_items[0], wallet_b.address_items[0])

            TEST_KEY = 'mytestkey'

            wallet_b.encrypt(TEST_KEY)
            wallet_b.save()

            self.assertEqual(1, len(wallet_b.address_items))
            self.assertNotEqual(wallet.address_items[0], wallet_b.address_items[0])

            wallet_c = Wallet()
            self.assertEqual(1, len(wallet_c.address_items))
            self.assertTrue(wallet_c.address_items[0].encrypted)

            wallet_c.decrypt(TEST_KEY)
            self.assertFalse(wallet_c.address_items[0].encrypted)
            self.assertEqual(wallet.address_items[0], wallet_c.address_items[0])

    def test_encrypted_wallet_rejects_tampered_seed(self):
        with set_qrl_dir('no_data'):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.encrypt('passphrase')
            wallet.save()
            with open(wallet.wallet_path) as infile:
                self.assertEqual(2, json.load(infile)['encryption_version'])
            encrypted = Wallet().address_items[0].hexseed
            self.assertTrue(encrypted.startswith('qrl-node-v2:'))

            wallet = Wallet()
            item = wallet.address_items[0]
            parts = item.hexseed.split(':')
            parts[-1] = ('0' if parts[-1][0] != '0' else '1') + parts[-1][1:]
            wallet.address_items[0] = item._replace(hexseed=':'.join(parts))
            with self.assertRaises(WalletDecryptionError):
                wallet.decrypt('passphrase')

    def test_versioned_wallet_rejects_legacy_ciphertext_substitution(self):
        with set_qrl_dir('no_data'):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            plain_seed = wallet.address_items[0].hexseed
            wallet.encrypt('passphrase')
            wallet.save()

            reloaded = Wallet()
            item = reloaded.address_items[0]
            reloaded.address_items[0] = item._replace(
                hexseed=AESHelper('passphrase').encrypt(plain_seed.encode()))
            with self.assertRaises(WalletDecryptionError):
                reloaded.decrypt('passphrase')
            with self.assertRaises(WalletEncryptionError):
                reloaded.save()

    def test_unknown_encryption_version_is_not_treated_as_legacy(self):
        with set_qrl_dir('no_data'):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.encrypt('passphrase')
            wallet.save()
            with open(wallet.wallet_path) as infile:
                data = json.load(infile)
            data['encryption_version'] = 99
            with open(wallet.wallet_path, 'w') as outfile:
                json.dump(data, outfile)

            with self.assertRaises(WalletVersionError):
                Wallet()

    def test_legacy_encrypted_wallet_can_migrate_without_plaintext_save(self):
        with set_qrl_dir('wallet_secure_ver1'):
            wallet = Wallet()
            self.assertFalse(wallet.address_items[0].hexseed.startswith('qrl-node-v2:'))
            wallet.decrypt('test1234')
            wallet.encrypt('test1234')
            wallet.save()

            migrated = Wallet()
            self.assertTrue(migrated.address_items[0].hexseed.startswith('qrl-node-v2:'))
            migrated.decrypt('test1234')
            self.assertEqual(wallet.address_items[0].qaddress,
                             migrated.address_items[0].qaddress)
