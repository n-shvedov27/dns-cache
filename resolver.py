import struct
import socket
import datetime
import struct

from threading import Lock, Thread

from server import BaseServer, BUFFER_SIZE
from cache import Cache, get_qname, set_padding

from random import randint

TYPES = {
    1: 'A', 2: 'NS', 3: 'MD', 4: 'MF', 5: 'CNAME',
    6: 'SOA', 7: 'MB', 8: 'MG', 9: 'MR', 10: 'NULL',
    11: 'WKS', 12: 'PTR', 13: 'HINFO', 14: 'MINFO',
    15: 'MX', 16: 'TXT'
}

MIN_VALUE = 50000
MAX_VALUE = 65536

CYCLE_MESSAGE = ('\n[-] Forwarder is corrupted (query was returned).\n'
                 '[!] Please, SHUTDOWN your server and specify another forwarder!')


class DNS(BaseServer):
    ''' Cached DNS resolver '''

    def __init__(self, port, forwarder):
        super(DNS, self).__init__(port)
        self._forwarder = forwarder
        self._forwarder_corrupted = False
        self._cache = Cache()
        self._lock = Lock()

    def _client_req_handler(self, addr, packet):
        print("In client request handler")
        self._client = addr

        if not self._forwarder_corrupted:
            if addr[0] == self._forwarder[0]:
                self._forwarder_corrupted = True
                print(CYCLE_MESSAGE)
                self._return_server_resp(self._make_error_packet(packet))
        else:
            self._return_server_resp(self._make_error_packet(packet))

        question = self._get_question(packet)
        qname = get_qname(question)
        qtype = struct.unpack('>H', question[question.find(b'\x00') + 1:][:2])[0]

        from_cache = False
        response = b''

        if self._cache.contains(qname, qtype):
            with self._lock:
                response, from_cache = self._cache.get(qname, qtype, packet[:2]), True
        if response in [b'', None]:
            response, from_cache = self._make_request2forwarder(qname, qtype, packet), False

        if not self._forwarder_corrupted:
            print("\n" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), end=" ")
            print("-- [*] {} {} {}".format(addr[0], TYPES[qtype], qname), end=" ")
            print('cache' if from_cache else 'forwarder')
            self._return_server_resp(response)

    def _get_question(self, packet):
        spacket = packet[12:]

        return spacket[:spacket.find(b'\x00') + 5]

    def _return_server_resp(self, packet):

        self._sock.sendto(packet, self._client)

    def _make_error_packet(self, packet):
        flags = '1' + set_padding(bin(packet[2])[2:])[1:]
        rcode = set_padding(bin(packet[3])[2:])

        return packet[:2] + struct.pack('>H', int(flags + rcode[:4] + '0010', 2)) + packet[4:]

    def _make_request2forwarder(self, qname, qtype, packet):
        if packet is None:
            return

        with self._lock:
            error = False
            sock = self._make_socket()
            try:
                sock.sendto(packet, self._forwarder)
                npacket, addr = sock.recvfrom(BUFFER_SIZE)
            except socket.error:
                self._return_server_resp(self._make_error_packet(packet))
            finally:
                sock.close()
            question = self._get_question(npacket)
            qnames = self._cache.push(qname, qtype, question, npacket)

            if qtype == 1:
                ns_packet = self.switch_a_to_ns(packet, qname)

                sock = self._make_socket()
                try:
                    sock.sendto(ns_packet, self._forwarder)
                    nepacket, addr = sock.recvfrom(BUFFER_SIZE)
                except socket.error:
                    self._return_server_resp(self._make_error_packet(packet))
                finally:
                    sock.close()
                question = self._get_question(nepacket)
                qnames = self._cache.push(qname, 2, question, nepacket)
                for auth_qname in qnames:
                    ns_packet = self.replace_qname(packet, qname, auth_qname)
                    sock = self._make_socket()
                    try:
                        sock.sendto(ns_packet, self._forwarder)
                        nepacket, addr = sock.recvfrom(BUFFER_SIZE)
                    except socket.error:
                        self._return_server_resp(self._make_error_packet(packet))
                    finally:
                        sock.close()

                    question = self._get_question(nepacket)
                    self._cache.push(auth_qname, 1, question, nepacket)

            # Thread(target=self.cache_inner_fields, args=(qnames,)).start()

            return npacket

    def replace_qname(self, packet, qname, new_qname):
        f_part = packet[:packet.find(bytes(qname.split('.')[0], 'utf8')) - 1]
        l_part = packet[packet.find(bytes(qname.split('.')[-2], 'utf8')) + len(qname.split('.')[-2])+1:]

        qwe = b''
        try:

            for w in new_qname.split('.'):
                qwe += struct.pack('>B', len(w)) + bytes(w, 'utf8')
        except:
            import sys
            print(sys.exc_info())
        return f_part + qwe + l_part

    def switch_a_to_ns(self, packet, qname):
        qname = qname.split('.')[-2]
        i = packet.find(bytes(qname, 'utf8')) + len(qname) + 2
        packet = packet[:i] + b'\x02' + packet[i + 1:]
        return packet

    def _check_if_query(self, packet):
        return set_padding(bin(packet[3])[2:])[0] == '0'

    def cache_inner_fields(self, qnames):
        for qname in qnames:
            if qname in [None, '']:
                continue
            for qtype in self._cache.used_qtypes:
                self._make_request2forwarder(qname, qtype,
                                             self.create_dns_request(qname, qtype))

    def create_dns_request(self, name, _type):
        with self._lock:
            name = name.encode()

            id = struct.pack('>H', randint(MIN_VALUE, MAX_VALUE))
            flags = b'\x01\x20'
            question = b'\x00\x01'
            answer = b'\x00\x00'
            authority = b'\x00\x00'
            addit = b'\x00\x00'

            qname = b''
            for part in name.split(b'.'):
                qname += struct.pack('B', len(part)) + part
            qtype = struct.pack('>H', _type)
            qclass = b'\x00\x01'
            return id + flags + question + answer + authority + addit + qname + qtype + qclass
