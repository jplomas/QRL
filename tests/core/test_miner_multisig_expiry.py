from unittest import TestCase
from unittest.mock import patch

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.Miner import Miner
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.State import State
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.txs.multisig.MultiSigCreate import MultiSigCreate
from qrl.core.txs.multisig.MultiSigSpend import MultiSigSpend
from qrl.core.txs.multisig.MultiSigVote import MultiSigVote
from tests.misc.helper import (cleanup_qrl_dir, get_alice_xmss, get_bob_xmss,
                               set_hard_fork_block_number, setup_qrl_dir_without_ctx)


class TestMinerMultiSigExpiry(TestCase):
    def setUp(self):
        qrl_dir, previous_qrl_dir = setup_qrl_dir_without_ctx('no_data')
        self.addCleanup(cleanup_qrl_dir, qrl_dir, previous_qrl_dir)

        hard_fork = set_hard_fork_block_number(new_value=1)
        hard_fork.__enter__()
        self.addCleanup(hard_fork.__exit__, None, None, None)

        clock = patch('qrl.core.misc.ntp.getTime', return_value=1615270948)
        clock.start()
        self.addCleanup(clock.stop)

        try:
            del GenesisBlock.instance
        except AttributeError:
            pass

        state = State()
        self.chain_manager = ChainManager(state)
        self.chain_manager.load(GenesisBlock())
        self.alice = get_alice_xmss(4)
        self.bob = get_bob_xmss(4)

        for signer in (self.alice, self.bob):
            account = OptimizedAddressState.get_default(signer.address)
            account.pbdata.balance = 1000
            OptimizedAddressState.put_optimized_addresses_state(state, {signer.address: account})

        creation = MultiSigCreate.create([self.alice.address], [1], 1, 0, self.alice.pk)
        creation.sign(self.alice)
        creation.pbdata.nonce = 1
        self.multi_sig_address = MultiSigAddressState.generate_multi_sig_address(creation.txhash)

        funding = TransferTransaction.create([self.multi_sig_address], [100], None, 0, self.bob.pk)
        funding.sign(self.bob)
        funding.pbdata.nonce = 1

        genesis = self.chain_manager.last_block
        setup_block = Block.create(config.dev, 1, genesis.headerhash, genesis.timestamp,
                                   [creation, funding], self.alice.address, 0, genesis.headerhash)
        self.assertTrue(self.chain_manager.add_block(setup_block))
        self.assertEqual(self.chain_manager.get_multi_sig_address_state(self.multi_sig_address).balance, 100)

        self.miner = Miner(self.chain_manager, lambda _: None, self.alice.address, 1)

    def _add_signed_spend(self, expiry_block_number):
        spend = MultiSigSpend.create(self.multi_sig_address, [self.bob.address], [100],
                                     expiry_block_number, 0, self.alice.pk)
        spend.sign(self.alice)
        spend.pbdata.nonce = 2
        self.assertTrue(spend.validate(True))
        self.assertTrue(self.chain_manager.validate_all(spend, check_nonce=False))
        self.assertTrue(self.chain_manager.tx_pool.add_tx_to_pool(spend, self.chain_manager.height))
        return spend

    def _next_block(self):
        return self.miner.create_block(self.chain_manager.last_block, 0,
                                       self.chain_manager.tx_pool, self.alice.address)

    def _confirm_spend_for_vote(self):
        spend = self._add_signed_spend(expiry_block_number=3)
        self.assertTrue(self.chain_manager.add_block(self._next_block()))
        self.assertEqual(self.chain_manager.height, 2)
        return spend

    def _add_signed_vote(self, spend):
        vote = MultiSigVote.create(spend.txhash, False, 0, self.alice.pk)
        vote.sign(self.alice)
        vote.pbdata.nonce = 3
        self.assertTrue(vote.validate(True))
        self.assertTrue(self.chain_manager.validate_all(vote, check_nonce=False))
        self.assertTrue(self.chain_manager.tx_pool.add_tx_to_pool(vote, self.chain_manager.height))
        return vote

    def test_next_block_expiry_is_dropped_before_assembly(self):
        spend = self._add_signed_spend(expiry_block_number=2)

        block = self._next_block()

        self.assertEqual(block.block_number, 2)
        self.assertNotIn(spend.txhash, [tx.transaction_hash for tx in block.transactions])
        self.assertEqual(len(self.chain_manager.tx_pool.transaction_pool), 0)
        self.assertTrue(self.chain_manager.add_block(block))
        self.assertEqual(self.chain_manager.height, 2)

    def test_later_expiry_is_included_and_applies(self):
        spend = self._add_signed_spend(expiry_block_number=3)

        block = self._next_block()

        self.assertIn(spend.txhash, [tx.transaction_hash for tx in block.transactions])
        self.assertTrue(self.chain_manager.add_block(block))
        self.assertEqual(self.chain_manager.height, 2)
        self.assertEqual(len(self.chain_manager.tx_pool.transaction_pool), 0)

    def test_vote_after_spend_expiry_is_dropped_before_assembly(self):
        spend = self._confirm_spend_for_vote()
        self.assertTrue(self.chain_manager.add_block(self._next_block()))
        self.assertEqual(self.chain_manager.height, 3)
        vote = self._add_signed_vote(spend)

        block = self._next_block()

        self.assertEqual(block.block_number, 4)
        self.assertNotIn(vote.txhash, [tx.transaction_hash for tx in block.transactions])
        self.assertEqual(len(self.chain_manager.tx_pool.transaction_pool), 0)
        self.assertTrue(self.chain_manager.add_block(block))

    def test_vote_at_spend_expiry_is_included_and_applies(self):
        spend = self._confirm_spend_for_vote()
        vote = self._add_signed_vote(spend)

        block = self._next_block()

        self.assertEqual(block.block_number, 3)
        self.assertIn(vote.txhash, [tx.transaction_hash for tx in block.transactions])
        self.assertTrue(self.chain_manager.add_block(block))
        self.assertEqual(self.chain_manager.height, 3)
