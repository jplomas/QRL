# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
import struct
import threading
from unittest import TestCase

from mock import Mock, patch, MagicMock
from pyqrllib.pyqrllib import hstr2bin, bin2hstr

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.p2p import p2pPeerManager
from qrl.core.p2p.p2pfactory import P2PFactory, p2p_msg_priority
from qrl.core.p2p.p2pprotocol import P2PProtocol
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrllegacy_pb2, qrl_pb2
from tests.misc.helper import replacement_getTime

logger.initialize_default()

Host = namedtuple('Host', ['host', 'port'])


def length_delimited(field, data):
    size = len(data)
    encoded_size = bytearray()
    while size >= 128:
        encoded_size.append((size & 0x7f) | 0x80)
        size >>= 7
    encoded_size.append(size)
    return bytes([(field << 3) | 2]) + bytes(encoded_size) + data


def block_frame(transaction_count):
    block = b'\x12\x00' * transaction_count
    return b'\x08\x05' + length_delimited(7, block)


# FIXME: These tests will soon be removed
class TestP2PProtocol(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestP2PProtocol, self).__init__(*args, **kwargs)

    def setUp(self):
        self.thread_patch = patch('qrl.core.p2p.p2pprotocol.reactor.callInThread',
                                  side_effect=lambda func, *args: func(*args))
        self.callback_patch = patch('qrl.core.p2p.p2pprotocol.reactor.callFromThread',
                                    side_effect=lambda func, *args: func(*args))
        self.thread_patch.start()
        self.callback_patch.start()
        self.addCleanup(self.thread_patch.stop)
        self.addCleanup(self.callback_patch.stop)
        with patch('qrl.core.misc.ntp.getTime', new=replacement_getTime):
            self.channel = P2PProtocol()

        self.channel._observable = Mock()

        self.channel.factory = Mock(autospec=P2PFactory)
        self.channel.factory.p2p_msg_priority = p2p_msg_priority
        self.channel.factory._qrl_node = Mock(autospec=QRLNode)
        self.channel.factory._qrl_node.peer_manager = Mock(autospec=p2pPeerManager)
        self.channel.factory._qrl_node.peer_manager.is_banned = MagicMock(return_value=False)
        self.channel.factory._qrl_node.peer_manager.trusted_addresses = MagicMock(return_value=[])

        sample_peer_1 = Host('127.0.0.2', '9000')
        sample_host = Host('127.0.0.1', '9000')
        attrs = {'getPeer.return_value': sample_peer_1, 'getHost.return_value': sample_host}
        self.channel.transport = Mock(**attrs)

    def tearDown(self):
        del self.channel

    def test_addr_remote_works(self):
        """
        This is more to ensure that the transport is mocked correctly.
        """
        self.assertEqual('127.0.0.2:9000', self.channel.peer.full_address)

    def test_addr_local_works(self):
        """
        This is more to ensure that the transport is mocked correctly.
        """
        self.assertEqual('127.0.0.1:9000', self.channel.host.full_address)

    @patch('qrl.core.misc.ntp.getTime')
    def test_connectionMade_behavior(self, getTime):
        """
        When connectionMade, the Managers (Observers) must be informed once, and peer list, version request messages
        must be in the outgoing message queue.
        ntp.getTime() is patched everywhere, not just in p2pprotocol, because OutgoingMessage uses it too.
        """
        self.channel.factory.get_connected_peer_addrs.return_value = {'127.0.0.2:9000'}

        getTime.return_value = 1525078652.9991353
        self.channel.connectionMade()

        # Managers were notified
        self.channel.transport.registerProducer.assert_called_once_with(self.channel, True)
        self.channel.p2pchain_manager.new_channel.assert_called_once_with(self.channel)
        self.channel.peer_manager.new_channel.assert_called_once_with(self.channel)
        self.channel.tx_manager.new_channel.assert_called_once_with(self.channel)

        # send_peer_list and send_version_request messages should be in the outgoing queue.
        self.assertEqual(self.channel.outgoing_queue.unfinished_tasks, 2)

    def test_connectionLost_behavior(self):
        """
        When connectionLost, peer_manager (an Observer) is notified. (why not other Observers?)
        """
        self.channel.connectionLost()
        self.channel.peer_manager.remove_channel.assert_called_once_with(self.channel)
        self.assertTrue(self.channel._producer_stopped)

    @patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
    def test_paused_producer_only_drains_on_resume(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                          veData=qrllegacy_pb2.VEData(version='test'))
        self.channel.pauseProducing()
        self.channel.send(msg)
        self.channel.send(msg)
        self.assertEqual(self.channel.transport.write.call_count, 0)
        self.assertEqual(self.channel._queued_bytes, 2 * len(self.channel._wrap_message(msg)))

        self.channel.resumeProducing()
        self.assertEqual(self.channel.transport.write.call_count, 2)
        self.assertEqual(self.channel._queued_bytes, 0)

    @patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
    def test_transport_pause_during_write_stops_drain(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                          veData=qrllegacy_pb2.VEData(version='test'))
        self.channel.pauseProducing()
        self.channel.send(msg)
        self.channel.send(msg)
        self.channel.transport.write.side_effect = lambda data: self.channel.pauseProducing()

        self.channel.resumeProducing()
        self.assertEqual(self.channel.transport.write.call_count, 1)
        self.assertEqual(self.channel._queued_bytes, len(self.channel._wrap_message(msg)))

    @patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
    def test_outgoing_byte_budget_disconnects_slow_peer(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                          veData=qrllegacy_pb2.VEData(version='test'))
        size = len(self.channel._wrap_message(msg))
        with patch.object(config.dev, 'max_bytes_out', size + 1):
            self.channel.pauseProducing()
            self.channel.send(msg)
            self.channel.send(msg)

        self.assertEqual(self.channel._queued_bytes, size)
        self.channel.transport.loseConnection.assert_called_once_with()

    @patch('qrl.core.p2p.p2pprotocol.reactor.callLater')
    @patch('qrl.core.misc.ntp.getTime')
    def test_rate_window_retries_without_peer_ack(self, getTime, callLater):
        getTime.return_value = 1000
        self.channel.rate_limit = 2
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                          veData=qrllegacy_pb2.VEData(version='test'))
        for _ in range(3):
            self.channel.send(msg)

        self.assertEqual(self.channel.transport.write.call_count, 2)
        self.assertEqual(callLater.call_count, 1)
        getTime.return_value = 1061
        callLater.call_args.args[1]()
        self.assertEqual(self.channel.transport.write.call_count, 3)
        self.assertEqual(self.channel._queued_bytes, 0)

    @patch('qrl.core.p2p.p2pprotocol.reactor.callLater')
    @patch('qrl.core.misc.ntp.getTime')
    def test_connection_lost_cancels_send_retry(self, getTime, callLater):
        getTime.return_value = 1000
        self.channel.rate_limit = 2
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                          veData=qrllegacy_pb2.VEData(version='test'))
        for _ in range(3):
            self.channel.send(msg)
        self.channel.connectionLost()
        callLater.return_value.cancel.assert_called_once_with()

    @patch('qrl.core.misc.ntp.getTime')
    def test_response_byte_and_key_limits_reset_each_minute(self, getTime):
        getTime.return_value = 100
        self.channel._response_window_at = 100
        with patch.object(config.dev, 'max_response_bytes_per_minute', 10), \
                patch.object(config.dev, 'max_responses_per_key_per_minute', 2):
            self.assertTrue(self.channel.may_serve_response(('block', 1), 4))
            self.assertTrue(self.channel.may_serve_response(('block', 1), 4))
            self.assertFalse(self.channel.may_serve_response(('block', 1), 1))
            self.assertFalse(self.channel.may_serve_response(('block', 2), 4))
            getTime.return_value = 160
            self.assertTrue(self.channel.may_serve_response(('block', 1), 4))

    @patch('qrl.core.misc.ntp.getTime')
    def test_dataReceived_normal_message(self, getTime):
        """
        Ensure that dataReceived works as expected with a normal message.
        """
        getTime.return_value = 1525078652.9991353
        data = b'\x00\x00\x00\x80\x08\x01"|\n\x0e66.175.217.203\n\x0e138.195.214.85\n\r35.177.72.178\n\x0e173.249.22.240\n\x0c2.238.131.20\n\r77.64.144.198\n\r34.208.138.15\n\x0f144.202.107.148\x00\x00\x00\x00'  # noqa
        self.channel.dataReceived(data)

        # Twisted transport should have received acknowledgement message to send out
        acknowledgement_bytes = b'\x00\x00\x00\x08\x08\x13\xaa\x01\x03\x08\x84\x01'
        self.channel.transport.write.assert_called_once_with(acknowledgement_bytes)

    @patch('qrl.core.misc.ntp.getTime')
    @patch('qrl.core.p2p.p2pprotocol.logger', autospec=True)
    @patch('qrl.core.p2p.p2pprotocol.config.dev', autospec=True)
    def test_dataReceived_too_big(self, config_dev, logger, getTime):
        """
        Normally the buffer size upper limit is 10MB. But we're going to patch it smaller here.
        """
        config_dev.max_bytes_out = 10
        config_dev.trust_min_msgcount = 10
        config_dev.reserved_quota = 10
        getTime.return_value = 1525078652.9991353
        acknowledgement_bytes = b'\x00\x00\x00\x08\x08\x13\xaa\x01\x03\x08\x88\x01'
        self.channel._buffer = 10 * acknowledgement_bytes
        self.channel.dataReceived(acknowledgement_bytes)
        self.channel.transport.loseConnection.assert_called()

    @patch('qrl.core.misc.ntp.getTime')
    def test_dataReceived_spam_ban_peer(self, getTime):
        getTime.return_value = 1525078652.9991353
        self.channel.rate_limit = 2
        acknowledgement_bytes = b'\x00\x00\x00\x08\x08\x13\xaa\x01\x03\x08\x88\x01'
        self.channel._buffer = 10 * acknowledgement_bytes
        self.channel.dataReceived(acknowledgement_bytes)
        self.channel.peer_manager.ban_channel.assert_called_with(self.channel)

    @patch('qrl.core.misc.ntp.getTime')
    def test_send_version_request(self, getTime):
        getTime.return_value = 1525078652.9991353
        version_request = b'\x00\x00\x00\x02\x1a\x00'
        self.channel.send_version_request()
        self.channel.transport.write.assert_called_with(version_request)

    @patch('qrl.core.misc.ntp.getTime')
    def test_send_sync(self, getTime):
        getTime.return_value = 1525078652.9991353
        self.channel.send_sync(synced=True)
        synced = b'\x00\x00\x00\r\x08\x10\x92\x01\x08\n\x06Synced'
        self.channel.transport.write.assert_called_with(synced)

        self.channel.send_sync(synced=False)
        unsynced = b'\x00\x00\x00\x05\x08\x10\x92\x01\x00'
        self.channel.transport.write.assert_called_with(unsynced)

    @patch('qrl.core.misc.ntp.getTime')
    def test_send_fetch_block(self, getTime):
        getTime.return_value = 1525078652.9991353
        block_request = b'\x00\x00\x00\x06\x08\x06B\x02\x08\x01'
        self.channel.send_fetch_block(1)
        self.channel.transport.write.assert_called_with(block_request)

    @patch('qrl.core.misc.ntp.getTime')
    def test_get_headerhash_list(self, getTime):
        getTime.return_value = 1525078652.9991353
        get_headerhash_request = b'\x00\x00\x00\x05\x08\x12\xa2\x01\x00'
        self.channel.send_get_headerhash_list(1)
        self.channel.transport.write.assert_called_with(get_headerhash_request)

    def test_parse_buffer_works(self):
        self.channel._buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368'
                                              + '000000191a170a0776657273696f6e120c67656e657369735f68617368'))
        messages = self.channel._parse_buffer([0])
        self.assertEqual(2, len(list(messages)))

    @patch('qrl.core.p2p.p2pprotocol.logger', autospec=True)
    def test_parse_buffer_invalid_data(self, logger):
        self.channel._buffer = bytes(hstr2bin('0000000000000000000000000000000000000000000000000000000000'
                                              + '1111111111111111111111111111111111111111111111111111111111'))

        messages = self.channel._parse_buffer([0])
        messages_list = list(messages)
        self.assertEqual(0, len(messages_list))
        logger.warning.assert_called_with("Problem parsing message. Banning+Dropping connection")

    def test_wrap_message_works(self):
        veData = qrllegacy_pb2.VEData(version="version", genesis_prev_hash=b'genesis_hash')
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE, veData=veData)
        self.assertEqual('000000191a170a0776657273696f6e120c67656e657369735f68617368',
                         bin2hstr(P2PProtocol._wrap_message(msg)))

    def test_block_record_limit_before_decode(self):
        with patch.object(config.dev, 'max_block_scan_records', 8):
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(block_frame(9))
            P2PProtocol._check_message_limits(block_frame(8))

    def test_block_and_nonblock_size_limits(self):
        with patch.object(config.dev, 'max_block_message_size', 32):
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(block_frame(20))

        peer_list = qrllegacy_pb2.LegacyMessage(
            func_name=qrllegacy_pb2.LegacyMessage.PL,
            plData=qrllegacy_pb2.PLData(peer_ips=['a' * 100]))
        with patch.object(config.dev, 'max_legacy_message_size', 64):
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(peer_list.SerializeToString())

    def test_duplicate_selector_or_block_payload_is_rejected(self):
        duplicate_selector = (b'\x08\x05' + length_delimited(4, length_delimited(1, b'x' * 80))
                              + b'\x08\x01')
        duplicate_block = b'\x08\x05' + length_delimited(7, b'') + length_delimited(7, b'\x12\x00' * 3)
        with patch.object(config.dev, 'max_legacy_message_size', 64):
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(duplicate_selector)
        with patch.object(config.dev, 'max_block_scan_records', 2):
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(duplicate_block)

    def test_pb_nested_duplicate_block_is_rejected(self):
        pb_data = length_delimited(1, b'') + length_delimited(1, b'\x12\x00' * 3)
        payload = b'\x08\x07' + length_delimited(9, pb_data)
        with patch.object(config.dev, 'max_block_scan_records', 2):
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(payload)

    def test_packed_and_proposal_records_are_bounded(self):
        packed_amounts = length_delimited(2, b'\x00' * 9)
        transfer = length_delimited(7, packed_amounts)
        packed_block = b'\x08\x05' + length_delimited(7, length_delimited(2, transfer))
        proposal_options = length_delimited(1, b'') * 9
        proposal = length_delimited(17, length_delimited(4, proposal_options))
        proposal_block = b'\x08\x05' + length_delimited(7, length_delimited(2, proposal))
        with patch.object(config.dev, 'max_block_scan_records', 8):
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(packed_block)
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(proposal_block)

    def test_repeated_nonblock_fields_are_bounded(self):
        peer_list = b'\x08\x01' + length_delimited(4, length_delimited(1, b'') * 9)
        with patch.object(config.dev, 'max_block_scan_records', 8):
            with self.assertRaises(ValueError):
                P2PProtocol._check_message_limits(peer_list)

    def test_dense_block_within_limit_is_accepted(self):
        tx = qrl_pb2.Transaction(public_key=b'k' * 67, signature=b's' * 2308)
        tx.transfer.addrs_to.extend([b'a' * 39] * 100)
        tx.transfer.amounts.extend([1] * 100)
        block = qrl_pb2.Block()
        for _ in range(313):
            block.transactions.add().CopyFrom(tx)
        message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.BK, block=block)
        payload = message.SerializeToString()
        self.assertLessEqual(len(payload), config.dev.max_block_message_size)
        P2PProtocol._check_message_limits(payload)

    def test_frame_limit_bans_before_observer_dispatch(self):
        payload = block_frame(9)
        with patch.object(config.dev, 'max_block_scan_records', 8):
            self.channel.dataReceived(struct.pack('>L', len(payload)) + payload)
        self.channel.peer_manager.ban_channel.assert_called_once_with(self.channel)
        self.channel._observable.notify.assert_not_called()

    def test_oversized_frame_header_is_rejected_before_body_arrives(self):
        with patch.object(config.dev, 'max_block_message_size', 64):
            self.channel.dataReceived(struct.pack('>L', 65) + b'x')
        self.channel.peer_manager.ban_channel.assert_called_once_with(self.channel)
        self.channel._observable.notify.assert_not_called()

    def test_normal_and_fragmented_frames_still_parse(self):
        version = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                              veData=qrllegacy_pb2.VEData(version='test'))
        block = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.BK)
        block.block.header.block_number = 1
        block.block.transactions.add().coinbase.SetInParent()
        for message in (version, block):
            P2PProtocol._check_message_limits(message.SerializeToString())
            wire = self.channel._wrap_message(message)
            for byte in wire:
                self.channel.dataReceived(bytes([byte]))
        self.assertEqual(self.channel._observable.notify.call_count, 2)

    def test_receive_decodes_off_reactor_in_peer_order(self):
        jobs = []
        version = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                              veData=qrllegacy_pb2.VEData(version='test'))
        peer_list = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                                plData=qrllegacy_pb2.PLData())
        wire = self.channel._wrap_message(version) + self.channel._wrap_message(peer_list)
        with patch('qrl.core.p2p.p2pprotocol.reactor.callInThread',
                   side_effect=lambda func, *args: jobs.append((func, args))):
            self.channel.dataReceived(wire)
            self.assertEqual(len(jobs), 1)
            self.channel._observable.notify.assert_not_called()
            self.channel.transport.pauseProducing.assert_called_once_with()

            func, args = jobs.pop(0)
            func(*args)
            self.assertEqual(self.channel._observable.notify.call_count, 1)
            self.assertEqual(len(jobs), 1)
            func, args = jobs.pop(0)
            func(*args)

        observed = [call.args[0].func_name for call in self.channel._observable.notify.call_args_list]
        self.assertEqual(observed, [qrllegacy_pb2.LegacyMessage.VE, qrllegacy_pb2.LegacyMessage.PL])
        self.assertEqual(self.channel.transport.write.call_count, 2)
        self.channel.transport.resumeProducing.assert_called_once_with()

    def test_worker_returns_decoded_message_to_reactor(self):
        callbacks = []
        futures = []
        reactor_thread = threading.get_ident()
        version = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                              veData=qrllegacy_pb2.VEData(version='test'))
        with ThreadPoolExecutor(max_workers=1) as pool, \
                patch('qrl.core.p2p.p2pprotocol.reactor.callInThread',
                      side_effect=lambda func, *args: futures.append(pool.submit(func, *args))), \
                patch('qrl.core.p2p.p2pprotocol.reactor.callFromThread',
                      side_effect=lambda func, *args: callbacks.append((func, args, threading.get_ident()))):
            self.channel.dataReceived(self.channel._wrap_message(version))
            futures[0].result()
            self.channel._observable.notify.assert_not_called()
            self.assertNotEqual(callbacks[0][2], reactor_thread)
            func, args, _ = callbacks[0]
            func(*args)

        self.channel._observable.notify.assert_called_once()
        self.assertEqual(self.channel.transport.write.call_count, 1)

    def test_global_worker_and_queue_budgets(self):
        jobs = []
        wire = self.channel._wrap_message(qrllegacy_pb2.LegacyMessage(
            func_name=qrllegacy_pb2.LegacyMessage.VE, veData=qrllegacy_pb2.VEData()))
        second = P2PProtocol()
        second.transport = Mock(getPeer=Mock(return_value=Host('127.0.0.4', '9000')))
        second.factory = self.channel.factory
        second._observable = Mock()
        third = P2PProtocol()
        third.transport = Mock(getPeer=Mock(return_value=Host('127.0.0.3', '9000')))
        with patch.object(config.dev, 'p2p_parse_workers', 1), \
                patch.object(config.dev, 'p2p_parse_queue_size', 1), \
                patch('qrl.core.p2p.p2pprotocol.reactor.callInThread',
                      side_effect=lambda func, *args: jobs.append((func, args))):
            self.channel.dataReceived(wire)
            second.dataReceived(wire)
            third.dataReceived(wire)
            self.assertEqual(len(jobs), 1)
            self.assertEqual(len(P2PProtocol._parse_queue), 1)
            third.transport.loseConnection.assert_called_once_with()

            func, args = jobs.pop(0)
            func(*args)
            self.assertEqual(len(jobs), 1)
            func, args = jobs.pop(0)
            func(*args)

        self.assertEqual(second._observable.notify.call_count, 1)
        self.assertEqual(P2PProtocol._parse_active, 0)
        self.assertEqual(len(P2PProtocol._parse_queue), 0)

    def test_disconnected_peer_drops_worker_result(self):
        jobs = []
        wire = self.channel._wrap_message(qrllegacy_pb2.LegacyMessage(
            func_name=qrllegacy_pb2.LegacyMessage.VE, veData=qrllegacy_pb2.VEData()))
        with patch('qrl.core.p2p.p2pprotocol.reactor.callInThread',
                   side_effect=lambda func, *args: jobs.append((func, args))):
            self.channel.dataReceived(wire)
            self.channel.connectionLost()
            func, args = jobs.pop(0)
            func(*args)

        self.channel._observable.notify.assert_not_called()
        self.channel.transport.write.assert_not_called()
        self.assertEqual(P2PProtocol._parse_active, 0)

    def test_queued_peer_disconnect_releases_frame(self):
        jobs = []
        wire = self.channel._wrap_message(qrllegacy_pb2.LegacyMessage(
            func_name=qrllegacy_pb2.LegacyMessage.VE, veData=qrllegacy_pb2.VEData()))
        second = P2PProtocol()
        second.transport = Mock(getPeer=Mock(return_value=Host('127.0.0.4', '9000')))
        second.factory = self.channel.factory
        second._observable = Mock()
        with patch.object(config.dev, 'p2p_parse_workers', 1), \
                patch('qrl.core.p2p.p2pprotocol.reactor.callInThread',
                      side_effect=lambda func, *args: jobs.append((func, args))):
            self.channel.dataReceived(wire)
            second.dataReceived(wire)
            self.assertEqual(len(P2PProtocol._parse_queue), 1)
            second.connectionLost()
            self.assertEqual(len(P2PProtocol._parse_queue), 0)
            func, args = jobs.pop(0)
            func(*args)

        second._observable.notify.assert_not_called()
        self.assertEqual(P2PProtocol._parse_active, 0)

    def test_malformed_worker_result_bans_before_dispatch(self):
        jobs = []
        raw = b'\xff' * 5
        with patch('qrl.core.p2p.p2pprotocol.reactor.callInThread',
                   side_effect=lambda func, *args: jobs.append((func, args))):
            self.channel.dataReceived(struct.pack('>L', len(raw)) + raw)
            self.channel._observable.notify.assert_not_called()
            func, args = jobs.pop(0)
            func(*args)

        self.channel.peer_manager.ban_channel.assert_called_once_with(self.channel)
        self.channel._observable.notify.assert_not_called()
