import threading
from unittest import TestCase

from mock import Mock, patch

from qrl.core import config
from qrl.core.ChainManager import ChainManager


class TestPoWFailureLogging(TestCase):
    def setUp(self):
        self.manager = ChainManager.__new__(ChainManager)
        self.manager.lock = threading.RLock()
        self.manager._state = Mock()
        self.manager.get_measurement = Mock(return_value=60)
        self.manager.get_seed_block = Mock(return_value=Mock(block_number=0, headerhash=b'seed'))
        self.header = Mock(block_number=1, prev_headerhash=b'parent', timestamp=1)
        self.header.mining_blob.return_value = b'mining-blob'

    def test_failed_pow_does_not_hash_again_for_logging(self):
        with patch('qrl.core.ChainManager.BlockMetadata.get_block_metadata',
                   return_value=Mock(block_difficulty=b'difficulty')), \
                patch('qrl.core.ChainManager.Block.get_block', return_value=Mock(timestamp=0)), \
                patch('qrl.core.ChainManager.DifficultyTracker.get',
                      return_value=(b'difficulty', b'target')), \
                patch('qrl.core.ChainManager.UInt256ToString', return_value='1'), \
                patch('qrl.core.ChainManager.PoWValidator') as validator, \
                patch('qrl.core.ChainManager.Qryptonight') as hasher:
            validator.return_value.verify_input.return_value = False
            hasher.return_value.hash.return_value = b'\x00' * 32

            self.assertFalse(self.manager.validate_mining_nonce(self.header, config.dev))
            validator.return_value.verify_input.assert_called_once_with(1, 0, b'seed', b'mining-blob', b'target')
            hasher.return_value.hash.assert_not_called()

    def test_valid_pow_still_returns_true(self):
        with patch('qrl.core.ChainManager.BlockMetadata.get_block_metadata',
                   return_value=Mock(block_difficulty=b'difficulty')), \
                patch('qrl.core.ChainManager.Block.get_block', return_value=Mock(timestamp=0)), \
                patch('qrl.core.ChainManager.DifficultyTracker.get',
                      return_value=(b'difficulty', b'target')), \
                patch('qrl.core.ChainManager.UInt256ToString', return_value='1'), \
                patch('qrl.core.ChainManager.PoWValidator') as validator, \
                patch('qrl.core.ChainManager.Qryptonight') as hasher:
            validator.return_value.verify_input.return_value = True
            hasher.return_value.hash.return_value = b'\x00' * 32

            self.assertTrue(self.manager.validate_mining_nonce(self.header, config.dev))
            validator.return_value.verify_input.assert_called_once_with(1, 0, b'seed', b'mining-blob', b'target')
            hasher.return_value.hash.assert_not_called()
