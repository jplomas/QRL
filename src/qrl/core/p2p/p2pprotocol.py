# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import struct
from collections import deque
from queue import PriorityQueue
from typing import Callable, Optional

from google.protobuf.json_format import MessageToJson
from pyqrllib.pyqrllib import bin2hstr  # noqa
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, connectionDone

from qrl.core import config
from qrl.core.OutgoingMessage import OutgoingMessage
from qrl.core.misc import logger, ntp
from qrl.core.p2p.IPMetadata import IPMetadata
from qrl.core.p2p.p2pObservable import P2PObservable
from qrl.generated import qrllegacy_pb2, qrl_pb2

OUT_FACTOR = 0.9
IN_FACTOR = 2.2

_BLOCK = qrllegacy_pb2.LegacyMessage.BK
_PUSH_BLOCK = qrllegacy_pb2.LegacyMessage.PB
_TRANSACTION_FIELDS = frozenset(range(11, 17)) | frozenset(range(22, 25))
_PACKED_FIELDS = {7: frozenset({2}), 12: frozenset({3}),
                  13: frozenset({2}), 14: frozenset({2}), 15: frozenset({3})}


def _read_varint(data, position, end):
    value = 0
    shift = 0
    while position < end and shift <= 63:
        byte = data[position]
        position += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, position
        shift += 7
    raise ValueError('Invalid protobuf varint')


def _read_field(data, position, end):
    tag, position = _read_varint(data, position, end)
    field, wire_type = tag >> 3, tag & 7
    if field == 0:
        raise ValueError('Invalid protobuf field number')
    if wire_type == 0:
        _, position = _read_varint(data, position, end)
        return field, wire_type, None, None, position
    if wire_type == 1:
        field_end = position + 8
    elif wire_type == 2:
        length, position = _read_varint(data, position, end)
        field_end = position + length
    elif wire_type == 5:
        field_end = position + 4
    else:
        raise ValueError('Unsupported protobuf wire type')
    if field_end > end:
        raise ValueError('Protobuf field overruns frame')
    if wire_type == 2:
        return field, wire_type, position, field_end, field_end
    return field, wire_type, None, None, field_end


def _scan_top_level(data):
    position, end = 0, len(data)
    func_name = None
    payload = None
    fields_seen = 0
    while position < end:
        fields_seen += 1
        if fields_seen > config.dev.max_block_scan_records:
            raise ValueError('Too many fields in P2P frame')
        tag, tag_end = _read_varint(data, position, end)
        field, wire_type = tag >> 3, tag & 7
        if field == 1 and wire_type == 0:
            if func_name is not None:
                raise ValueError('Repeated P2P message selector')
            func_name, position = _read_varint(data, tag_end, end)
            continue
        field, wire_type, start, stop, position = _read_field(data, position, end)
        if 2 <= field <= 24 and wire_type == 2:
            if payload is not None:
                raise ValueError('Repeated P2P message payload')
            payload = (field, start, stop)
    return func_name, payload


def _single_submessage(data, position, end, wanted_field):
    found = None
    fields_seen = 0
    while position < end:
        fields_seen += 1
        if fields_seen > config.dev.max_block_scan_records:
            raise ValueError('Too many fields in P2P submessage')
        field, wire_type, start, stop, position = _read_field(data, position, end)
        if field == wanted_field and wire_type == 2:
            if found is not None:
                raise ValueError('Repeated P2P block payload')
            found = (start, stop)
    return found


def _count_records(data, position, end, kind, count, packed_fields=frozenset()):
    while position < end:
        count[0] += 1
        if count[0] > config.dev.max_block_scan_records:
            raise ValueError('Too many records in P2P frame')
        field, wire_type, start, stop, position = _read_field(data, position, end)
        if wire_type != 2:
            continue

        if field in packed_fields:
            while start < stop:
                _, start = _read_varint(data, start, stop)
                count[0] += 1
                if count[0] > config.dev.max_block_scan_records:
                    raise ValueError('Too many records in P2P frame')
        elif kind == 'block' and field == 2:
            _count_records(data, start, stop, 'transaction', count)
        elif kind == 'transaction' and 7 <= field <= 18:
            child_kind = 'proposal' if field == 17 else 'payload'
            _count_records(data, start, stop, child_kind, count, _PACKED_FIELDS.get(field, frozenset()))
        elif kind == 'proposal' and field in (3, 4, 5):
            _count_records(data, start, stop, 'payload', count)


# Rename to p2p channel
class P2PProtocol(Protocol):
    _parse_active = 0
    _parse_queue = deque()

    def __init__(self):
        self._buffer = bytes()
        self._parse_pending = False
        self._receiving_stopped = False
        self._reading_paused = False

        # Need to use composition instead of inheritance here
        self._observable = P2PObservable(self)

        self.last_rate_limit_update = 0
        self.rate_limit = config.user.peer_rate_limit
        self.in_counter = 0
        self.out_counter = 0

        self.bytes_sent = 0
        self._queued_bytes = 0
        self._producer_paused = False
        self._producer_stopped = False
        self._send_retry = None
        self._response_window_at = ntp.getTime()
        self._response_bytes = 0
        self._response_keys = {}
        self.outgoing_queue = PriorityQueue(maxsize=config.user.p2p_q_size)

        self._connected_at = ntp.getTime()
        self._valid_message_count = 0

        self._public_port = 0

        self._peer_list_already_handled = False

    @property
    def peer(self):
        return IPMetadata(self.transport.getPeer().host, self.transport.getPeer().port)

    @property
    def host(self):
        return IPMetadata(self.transport.getHost().host, self.transport.getHost().port)

    @property
    def public_port(self):
        return self._public_port

    @property
    def ip_public_port(self):
        return "{}:{}".format(self.transport.getPeer().host, self._public_port)

    @property
    def connected_at(self):
        return self._connected_at

    @property
    def valid_message_count(self):
        return self._valid_message_count

    @property
    def connection_time(self):
        return ntp.getTime() - self._connected_at

    @property
    def peer_manager(self):
        # FIXME: this is breaking encapsulation
        return self.factory._qrl_node.peer_manager

    @property
    def p2pchain_manager(self):
        # FIXME: this is breaking encapsulation
        return self.factory._qrl_node.p2pchain_manager

    @property
    def tx_manager(self):
        # FIXME: this is breaking encapsulation
        return self.factory._qrl_node.tx_manager

    def set_public_port(self, public_port):
        self._public_port = public_port

    def register(self, message_type, func: Callable):
        self._observable.register(message_type, func)

    def connectionMade(self):
        if self.factory.add_connection(self):
            self.transport.registerProducer(self, True)
            self.peer_manager.new_channel(self)
            self.p2pchain_manager.new_channel(self)
            self.tx_manager.new_channel(self)

            self.send_peer_list()
            self.send_version_request()
        else:
            self.loseConnection()

    def connectionLost(self, reason=connectionDone):
        self._stop_receiving()
        self.stopProducing()
        logger.debug('%s disconnected. remainder connected: %d', self.peer, self.factory.num_connections)

        self.factory.remove_connection(self)
        if self.peer_manager:
            self.peer_manager.remove_channel(self)

    def dataReceived(self, data: bytes) -> None:
        if self._receiving_stopped:
            return
        if len(self._buffer) + len(data) > config.dev.max_bytes_out + config.dev.reserved_quota:
            logger.warning('Disconnecting peer %s', self.peer)
            logger.warning('Buffer Size %s', len(self._buffer))
            logger.warning('Incoming Data Size %s', len(data))
            self._buffer = b''  # Empty buffer
            self.loseConnection()
            return

        self._buffer += data

        self._drain_receive_buffer()

    def _stop_receiving(self):
        self._receiving_stopped = True
        self._buffer = b''
        self._parse_pending = False
        cls = type(self)
        cls._parse_queue = deque(job for job in cls._parse_queue if job[0] is not self)

    def _resume_receiving(self):
        if self._reading_paused:
            self._reading_paused = False
            self.transport.resumeProducing()

    def _drain_receive_buffer(self):
        if self._parse_pending or self._receiving_stopped:
            return
        if len(self._buffer) < 4:
            self._resume_receiving()
            return

        chunk_size = struct.unpack('>L', self._buffer[:4])[0]
        if (chunk_size <= 0 or chunk_size > config.dev.message_buffer_size or
                chunk_size > config.dev.max_block_message_size):
            logger.warning('Invalid P2P frame size %s from %s', chunk_size, self.peer)
            self._receiving_stopped = True
            self.peer_manager.ban_channel(self)
            return
        if len(self._buffer) - 4 < chunk_size:
            self._resume_receiving()
            return

        raw = self._buffer[4:4 + chunk_size]
        self._buffer = self._buffer[4 + chunk_size:]
        self._parse_pending = True
        if not self._reading_paused:
            self._reading_paused = True
            self.transport.pauseProducing()
        cls = type(self)
        if cls._parse_active < config.dev.p2p_parse_workers:
            cls._start_parse(self, raw, chunk_size + 4)
        elif len(cls._parse_queue) < config.dev.p2p_parse_queue_size:
            cls._parse_queue.append((self, raw, chunk_size + 4))
        else:
            logger.warning('P2P parse queue full; disconnecting %s', self.peer)
            self.loseConnection()

    @classmethod
    def _start_parse(cls, channel, raw, wire_size):
        cls._parse_active += 1
        try:
            reactor.callInThread(channel._decode_in_worker, raw, wire_size)
        except Exception:
            cls._parse_active -= 1
            logger.exception('Could not schedule P2P decode')
            channel.loseConnection()

    @classmethod
    def _start_queued_parse(cls):
        while cls._parse_queue and cls._parse_active < config.dev.p2p_parse_workers:
            channel, raw, wire_size = cls._parse_queue.popleft()
            if not channel._receiving_stopped:
                cls._start_parse(channel, raw, wire_size)
                return

    def _decode_in_worker(self, raw, wire_size):
        message, error = None, None
        try:
            self._check_message_limits(raw)
            message = qrllegacy_pb2.LegacyMessage()
            message.ParseFromString(raw)
        except Exception as exc:
            error = exc
        reactor.callFromThread(self._parse_finished, message, error, wire_size)

    def _parse_finished(self, message, error, wire_size):
        cls = type(self)
        cls._parse_active -= 1
        self._parse_pending = False
        cls._start_queued_parse()
        if self._receiving_stopped:
            return
        if error is not None:
            logger.warning('Problem parsing message. Banning+Dropping connection: %s', error)
            self._receiving_stopped = True
            self.peer_manager.ban_channel(self)
            return

        self.update_counters()
        self.in_counter += 1
        if self.in_counter > self.rate_limit * IN_FACTOR:
            logger.warning('Rate Limit hit by %s %s', self.peer.ip, self.peer.port)
            self._receiving_stopped = True
            self.peer_manager.ban_channel(self)
            return

        if self._valid_message_count < config.dev.trust_min_msgcount * 2:
            self._valid_message_count += 1
        try:
            self._observable.notify(message)
        except Exception:
            logger.exception('P2P message observer failed')
            self.loseConnection()
            return

        if not self._receiving_stopped and message.func_name != qrllegacy_pb2.LegacyMessage.P2P_ACK:
            ack = qrl_pb2.P2PAcknowledgement(bytes_processed=wire_size)
            self.send(qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.P2P_ACK,
                                                  p2pAckData=ack))
        self._drain_receive_buffer()

    def update_counters(self):
        time_diff = ntp.getTime() - self.last_rate_limit_update
        if time_diff > 60:
            self.out_counter = 0
            self.in_counter = 0
            self.last_rate_limit_update = ntp.getTime()
            return

    def send_next(self):
        if self._producer_paused or self._producer_stopped:
            return

        self.update_counters()
        while not self._producer_paused and not self._producer_stopped and self.out_counter < self.rate_limit * OUT_FACTOR:
            outgoing_bytes = self.get_bytes_from_q()
            if not outgoing_bytes:
                break
            self.bytes_sent += len(outgoing_bytes)
            self.transport.write(outgoing_bytes)

        if (not self._producer_paused and not self._producer_stopped and
                not self.outgoing_queue.empty() and self.out_counter >= self.rate_limit * OUT_FACTOR and
                self._send_retry is None):
            delay = max(0.01, self.last_rate_limit_update + 60.01 - ntp.getTime())
            self._send_retry = reactor.callLater(delay, self._retry_send)

    def _retry_send(self):
        self._send_retry = None
        self.send_next()

    def get_bytes_from_q(self):
        while not self.outgoing_queue.empty():
            outgoing_msg = self.outgoing_queue.get()[2]
            self._queued_bytes -= len(outgoing_msg.wire_bytes)
            if not outgoing_msg.is_expired():
                self.out_counter += 1
                return outgoing_msg.wire_bytes

        return b''

    def may_serve_response(self, key, size):
        now = ntp.getTime()
        if now - self._response_window_at >= 60:
            self._response_window_at = now
            self._response_bytes = 0
            self._response_keys.clear()

        if (self._response_keys.get(key, 0) >= config.dev.max_responses_per_key_per_minute or
                self._response_bytes + size > config.dev.max_response_bytes_per_minute):
            return False

        self._response_keys[key] = self._response_keys.get(key, 0) + 1
        self._response_bytes += size
        return True

    def send(self, message: qrllegacy_pb2.LegacyMessage):
        if self._producer_stopped:
            return
        priority = self.factory.p2p_msg_priority[message.func_name]
        if self.outgoing_queue.full():
            logger.info("Outgoing Queue Full: Skipping Message Type %s", message.WhichOneof('data'))
            return

        if message.ByteSize() + 4 > config.dev.max_bytes_out:
            logger.warning('Disconnecting peer %s: outgoing message exceeds byte limit', self.peer)
            self.loseConnection()
            return

        wire_bytes = self._wrap_message(message)
        if wire_bytes is None:
            return
        if self._queued_bytes + len(wire_bytes) > config.dev.max_bytes_out:
            logger.warning('Disconnecting slow peer %s: outgoing queue exceeds byte limit', self.peer)
            self.loseConnection()
            return

        outgoing_msg = OutgoingMessage(priority, message, wire_bytes)
        self.outgoing_queue.put((outgoing_msg.priority, outgoing_msg.timestamp, outgoing_msg))
        self._queued_bytes += len(wire_bytes)
        self.send_next()

    def pauseProducing(self):
        self._producer_paused = True

    def resumeProducing(self):
        if self._producer_stopped:
            return
        self._producer_paused = False
        self.send_next()

    def stopProducing(self):
        self._producer_stopped = True
        if self._send_retry is not None:
            self._send_retry.cancel()
            self._send_retry = None

    def loseConnection(self):
        self._stop_receiving()
        self.transport.loseConnection()

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    # Low-level serialization/connections/etc
    # FIXME: This is a temporary refactoring, it will be completely replaced before release

    @staticmethod
    def _wrap_message(protobuf_obj) -> Optional[bytes]:
        """
        Receives a protobuf object and encodes it as (length)(data)
        :return: the encoded message
        :rtype: bytes
        >>> veData = qrllegacy_pb2.VEData(version="version", genesis_prev_hash=b'genesis_hash')
        >>> msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE, veData=veData)
        >>> bin2hstr(P2PProtocol._wrap_message(msg))
        '000000191a170a0776657273696f6e120c67656e657369735f68617368'

                msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                          plData=qrllegacy_pb2.PLData(peer_ips=trusted_peers,
                                                                      public_port=config.user.p2p_public_port))

        >>> plData = qrllegacy_pb2.PLData(peer_ips=[])
        >>> msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL, plData=plData)
        >>> bin2hstr(P2PProtocol._wrap_message(msg))
        '0000000408012200'
        """
        data = protobuf_obj.SerializeToString()
        if len(data) == 0:
            logger.debug("Skipping message. Zero bytes. %s", MessageToJson(protobuf_obj, sort_keys=True))
            return None

        str_data_len = struct.pack('>L', len(data))
        return str_data_len + data

    @staticmethod
    def _check_message_limits(message_raw):
        if len(message_raw) > config.dev.max_block_message_size:
            raise ValueError('P2P block frame exceeds size limit')

        func_name, payload = _scan_top_level(message_raw)
        if func_name in (_BLOCK, _PUSH_BLOCK):
            expected_field = 7 if func_name == _BLOCK else 9
            if payload is None or payload[0] != expected_field:
                raise ValueError('Invalid P2P block payload')
            if func_name == _BLOCK:
                block = payload[1:]
            else:
                block = _single_submessage(message_raw, payload[1], payload[2], 1)
            if block is None:
                raise ValueError('Missing P2P block payload')
            _count_records(message_raw, block[0], block[1], 'block', [0])
            return

        if len(message_raw) > config.dev.max_legacy_message_size:
            raise ValueError('P2P message exceeds size limit')
        if payload is not None:
            if payload[0] in (7, 9):
                raise ValueError('Block payload without block selector')
            kind = 'transaction' if payload[0] in _TRANSACTION_FIELDS else 'payload'
            _count_records(message_raw, payload[1], payload[2], kind, [0])

    def _parse_buffer(self, total_read):
        # FIXME: This parsing/wire protocol needs to be replaced
        """
        >>> from pyqrllib.pyqrllib import hstr2bin
        >>> p=P2PProtocol()
        >>> p._buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368'+ \
                                       '000000191a170a0776657273696f6e120c67656e657369735f68617368'))
        >>> messages = p._parse_buffer([0])
        >>> len(list(messages))
        2
        """

        chunk_size = 0

        while self._buffer:
            if len(self._buffer) < 5:
                # Buffer is still incomplete as it doesn't have message size
                return

            ignore_skip = False

            try:
                chunk_size_raw = self._buffer[:4]
                chunk_size = struct.unpack('>L', chunk_size_raw)[0]  # is m length encoded correctly?

                if chunk_size <= 0:
                    logger.debug("<X< %s", bin2hstr(self._buffer))
                    raise Exception("Invalid chunk size <= 0")

                if chunk_size > config.dev.message_buffer_size:
                    raise Exception("Invalid chunk size > message_buffer_size")
                if chunk_size > config.dev.max_block_message_size:
                    raise ValueError('P2P frame exceeds size limit')

                if len(self._buffer) - 4 < chunk_size:  # As 4 bytes includes chunk_size_raw
                    ignore_skip = True  # Buffer is still incomplete as it doesn't have message so skip moving buffer
                    return

                message_raw = self._buffer[4:4 + chunk_size]
                self._check_message_limits(message_raw)
                message = qrllegacy_pb2.LegacyMessage()
                message.ParseFromString(message_raw)
                yield message

            except Exception as e:  # no qa
                logger.warning("Problem parsing message. Banning+Dropping connection")
                logger.exception(e)
                self.peer_manager.ban_channel(self)
                return

            finally:
                if not ignore_skip:
                    skip = 4 + chunk_size
                    self._buffer = self._buffer[skip:]
                    total_read[0] += skip

    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def send_version_request(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                          veData=qrllegacy_pb2.VEData())
        self.send(msg)

    def send_peer_list(self):
        """
        Get Peers
        Sends the peers list.
        :return:
        """
        trusted_peers = self.peer_manager.trusted_addresses
        logger.debug('<<< Sending connected peers to %s [%s]', self.peer, trusted_peers)

        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                          plData=qrllegacy_pb2.PLData(peer_ips=trusted_peers,
                                                                      public_port=config.user.p2p_public_port))

        self.send(msg)

    def send_sync(self, synced=False):
        state_str = ''
        if synced:
            state_str = 'Synced'

        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                          syncData=qrllegacy_pb2.SYNCData(state=state_str))
        self.send(msg)

    def send_fetch_block(self, block_idx):
        """
        Fetch Block n
        Sends request for the block number n.
        :return:
        """
        logger.info('<<<Fetching block: %s from %s', block_idx, self.peer)
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.FB,
                                          fbData=qrllegacy_pb2.FBData(index=block_idx))
        self.send(msg)

    def send_get_headerhash_list(self, current_block_height):
        start_blocknumber = max(0, current_block_height - config.dev.reorg_limit)
        node_header_hash = qrl_pb2.NodeHeaderHash(block_number=start_blocknumber,
                                                  headerhashes=[])
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.HEADERHASHES,
                                          nodeHeaderHash=node_header_hash)
        self.send(msg)
