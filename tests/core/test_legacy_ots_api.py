from unittest import TestCase
from unittest.mock import Mock, patch

from qrl.core import config
from qrl.core.ChainManager import ChainManager
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.qrlnode import QRLNode


def address_for_height(height):
    address = bytearray(39)
    address[1] = height // 2
    return bytes(address)


class TestLegacyOTSAPI(TestCase):
    def make_chain_manager(self, height):
        manager = object.__new__(ChainManager)
        address = address_for_height(height)
        state = OptimizedAddressState.get_default(address)
        manager.get_optimized_address_state = Mock(return_value=state)
        manager.get_bitfield = Mock()
        return manager, address

    def test_legacy_response_rejects_large_bitfield_before_reading_pages(self):
        manager, address = self.make_chain_manager(30)
        with self.assertRaisesRegex(ValueError, 'legacy API limit'):
            manager.get_address_state(address, exclude_transaction_hashes=True)
        manager.get_bitfield.assert_not_called()

        state = manager.get_address_state(address, exclude_ots_bitfield=True,
                                          exclude_transaction_hashes=True)
        self.assertEqual(len(state.ots_bitfield), 0)

    def test_legacy_page_two_starts_at_byte_1024(self):
        manager, address = self.make_chain_manager(14)
        page_one = [b'\xff'] * config.dev.ots_bitfield_size
        page_two = [b'\x01'] + [b'\x00'] * (config.dev.ots_bitfield_size - 1)
        manager.get_bitfield.side_effect = [page_one, page_two]

        state = manager.get_address_state(address, exclude_transaction_hashes=True)
        self.assertEqual(len(state.ots_bitfield), 2048)
        self.assertEqual(state.ots_bitfield[1024], b'\x01')
        self.assertEqual(state.get_unused_ots_index(0), 8193)

        manager.get_bitfield.side_effect = [[b'\xff'] * config.dev.ots_bitfield_size] * 2
        full_state = manager.get_address_state(address, exclude_transaction_hashes=True)
        self.assertIsNone(full_state.get_unused_ots_index(0))

    @patch.object(OptimizedAddressState, 'address_is_valid', return_value=True)
    def test_get_ots_bounds_page_count_and_scan(self, address_is_valid):
        node = object.__new__(QRLNode)
        node._chain_manager = Mock()
        address = address_for_height(30)

        with self.assertRaisesRegex(ValueError, 'page count'):
            node.get_ots(address, 1, config.dev.max_get_ots_pages + 1, 0)
        node._chain_manager.get_bitfield.assert_not_called()

        node._chain_manager.get_bitfield.return_value = [b'\x00'] * config.dev.ots_bitfield_size
        node._chain_manager.get_unused_ots_index2.return_value = 42
        pages, unused, found = node.get_ots(address, 1, 1, 0)
        self.assertEqual(len(pages), 1)
        self.assertEqual((unused, found), (42, True))
        node._chain_manager.get_unused_ots_index2.assert_called_once_with(
            address, 0, max_scan_keys=config.dev.max_get_ots_scan_keys)

    def test_get_ots_scan_limit_is_an_error_not_false_exhaustion(self):
        manager, address = self.make_chain_manager(30)
        paginated = Mock()
        paginated.generate_bitfield_key.return_value = b'page'
        paginated.get_paginated_data.return_value = [b'\xff'] * config.dev.ots_bitfield_size

        with self.assertRaisesRegex(ValueError, 'retry from index 16'):
            manager.get_unused_ots_index({}, {}, address, paginated, max_scan_keys=16)

        paginated.get_paginated_data.return_value = [b'\x07'] + [b'\x00'] * (config.dev.ots_bitfield_size - 1)
        self.assertEqual(manager.get_unused_ots_index({}, {}, address, paginated, max_scan_keys=16), 3)
