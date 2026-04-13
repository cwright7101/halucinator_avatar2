#/usr/bin/env python

import logging
import re
import socket
import binascii
import struct

import xml.etree.ElementTree as ET
from time import sleep
from collections import defaultdict, OrderedDict
from struct import pack
from types import MethodType
from threading import Thread, Event
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from os.path import dirname
from avatar2.protocols.gdb import GDBProtocol
from avatar2.targets import TargetStates


l = logging.getLogger('avatar2.gdbplugin')

chksum = lambda x: sum(x) & 0xff
match_hex = lambda m, s: [int(x, 16) for x in re.match(m, s).groups()]

TIMEOUT_TIME = 1.0


class GDBRSPServer(Thread):

    def __init__(self, avatar, target, port=3333, xml_file=None,
                 do_forwarding=False):
        super().__init__()
        self.daemon=True
        self.sock = socket.socket(AF_INET, SOCK_STREAM)
        self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        self.avatar = avatar
        self.target = target
        self.port = port
        self.xml_file = xml_file
        self.do_forwarding = do_forwarding

        self.xml_files = defaultdict(list)

        self._packetsize=0x47FF
        self.running = False
        self.bps = {}
        self._do_shutdown = Event()

        # Optional callback: stop_filter(target, pc) -> bool
        # If set and returns True, the stop is suppressed (not reported to
        # the GDB client). This allows external frameworks to silently handle
        # certain breakpoints (e.g. intercepts) without the client seeing them.
        self.stop_filter = None

        # Register list populated lazily from target XML on first connection
        self.registers = []

        # Handler dispatch. Data packets (g/G/p/P/m/M) get forwarded
        # directly to QEMU's internal GDB stub via forward_or_fallback.
        # That avoids doing N per-register round trips on every single-
        # step, which is what made the GDB-backed debug UI feel sluggish
        # compared to the custom DAP variant. The explicit per-register
        # handlers remain as fallbacks when no GDBProtocol is attached
        # to the target.
        self.handlers = {
            'q' : self.query,
            'v' : self.multi_letter_cmd,
            'H' : self.set_thread_op,
            '?' : self.halt_reason,
            'g' : lambda pkt: self._forward_or_fallback(pkt, self.read_registers),
            'G' : lambda pkt: self._forward_or_fallback(pkt, self.reg_write),
            'p' : lambda pkt: self._forward_or_fallback(pkt, self.read_single_reg),
            'P' : lambda pkt: self._forward_or_fallback(pkt, self.write_single_reg),
            'm' : lambda pkt: self._forward_or_fallback(pkt, self.mem_read),
            'M' : lambda pkt: self._forward_or_fallback(pkt, self.mem_write),
            'c' : self.cont,
            'C' : self.cont,
            's' : self.step,
            'S' : self.step,
            'Z' : self.insert_breakpoint,
            'z' : self.remove_breakpoint,
            'D' : self.detach,
            'k' : self.kill,
        }

    def shutdown(self):
        self._do_shutdown.set()
        sleep(TIMEOUT_TIME*2)

    def run(self):

        l.info(f'GDB server listening on port {self.port}, please connect')
        self.sock.bind(('', self.port))
        self.sock.settimeout(TIMEOUT_TIME)
        self.sock.listen(1)
        
        while not self._do_shutdown.isSet():
            try:
                self.conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            self.conn.settimeout(TIMEOUT_TIME)
            l.info(f'Accepted connection from {addr}')

            if not self.target.state & TargetStates.STOPPED:
                self.target.stop()
            while self.conn._closed is False:
                packet = self.receive_packet()
                if packet is None:
                    continue

                l.debug(f'Received: {packet}')

                self.send_raw(b'+') # send ACK
                # resp = self.forward_pkt(packet)
                # l.debug("Sending Response %s" % resp)
                handler = self.handlers.get(chr(packet[0]),
                                                  self.not_implemented)
                resp = handler(packet)
                if resp is not None:
                    self.send_packet(resp)
        self.sock.close()


    ### Handlers
    def not_implemented(self, pkt):
        l.critical(f'Received not implemented packet: {pkt}')
        return b''


    def forward_pkt(self, pkt):
        ## TODO make  so reverts to old code if no GDBProtocol
        if hasattr(self.target.protocols,'execution') and \
            issubclass(type(self.target.protocols.execution), GDBProtocol):
            gdb = self.target.protocols.execution
            success, resp = gdb.console_command(f"maintenance packet {pkt.decode()}")
            if success:
                data = resp.split('received: \\"')[1][:-4]
                # Data has been escaped twice by time we get it.
                data = data.encode('utf-8').decode('unicode_escape')
                data = data.encode('utf-8').decode('unicode_escape')
                return data.encode()

    def _forward_or_fallback(self, pkt, fallback_handler):
        """
        Try forwarding the packet to QEMU's internal GDB stub for speed;
        fall back to a Python-implemented handler if forwarding isn't
        available (no GDBProtocol) or errors out. Used for data packets
        (g/G/p/P/m/M) where a single forwarded round-trip is vastly
        faster than the per-register or per-chunk Python loop.
        """
        try:
            forwarded = self.forward_pkt(pkt)
            if forwarded is not None:
                return forwarded
        except Exception as e:
            l.debug("forward_pkt failed for %s: %s", pkt[:1], e)
        return fallback_handler(pkt)

    def query(self, pkt):
        if pkt[1:].startswith(b'Supported') is True:
            feat = [b'PacketSize=%x' % self._packetsize,
                    b'qXfer:features:read+'
                   ]
            return b';'.join(feat)

        if pkt[1:].startswith(b'Attached') is True:
            return b'1'

        if pkt[1:].startswith(b'Xfer:features:read:') is True:
            request = pkt[1:].split(b':')
            l.debug("Request has %s"%request)
            filename = request[3]
            start_idx, rd_size = request[4].split(b",")
            start_idx = int(start_idx, 16)
            rd_size = int(rd_size, 16)

            # Try forwarding to the underlying GDB protocol connection
            # (if present). If anything goes wrong — parse error, protocol
            # not connected, empty console response — fall back to the
            # static xml_file. The previous implementation returned None
            # on forwarding failure, which sent no response on the wire
            # and made GDB hang on qSupported → qXfer:features:read
            # with "Bogus trace status reply from target: timeout".
            forwarded = None
            if hasattr(self.target.protocols, 'execution') and \
                    issubclass(type(self.target.protocols.execution), GDBProtocol):
                try:
                    l.debug("Forwarding request for %s", pkt[1:])
                    gdb = self.target.protocols.execution
                    success, resp = gdb.console_command(
                        f"maintenance packet {pkt.decode()}"
                    )
                    if success:
                        data = resp.split('received: \\"')[1][:-4]
                        # Data has been escaped twice by time we get it.
                        data = data.encode('utf-8').decode('unicode_escape')
                        data = data.encode('utf-8').decode('unicode_escape')

                        ret_data = data.encode()
                        l.debug("Ret_data %s" % ret_data)

                        payload = ret_data[1:]
                        self.xml_files[filename].append(payload)
                        if len(payload) < rd_size:
                            # This is last read of xml will want to parse it
                            xml_data = b''.join(self.xml_files[filename])

                            l.debug("Writing to %s: %s" % (filename, xml_data))
                            with open(filename, 'wb') as outfile:
                                outfile.write(xml_data)
                            try:
                                xml_regs = ET.fromstring(xml_data).find('feature')
                                if xml_regs:
                                    regs = [reg.attrib for reg in xml_regs
                                            if reg.tag == 'reg']
                                    l.debug("Adding registers %s" % regs)
                                    self.registers.extend(regs)
                            except ET.ParseError as e:
                                l.debug("Parsing Error: %s" % e)
                                pass
                        forwarded = ret_data
                except Exception as e:
                    l.warning(
                        "Forwarding qXfer:features:read failed (%s); "
                        "falling back to static xml_file", e
                    )

            if forwarded is not None:
                return forwarded

            # Fallback: serve the static xml_file that ships with avatar2.
            # This path is what test suites exercise and is reliable even
            # when there's no GDB protocol attached to the target.
            off, length = match_hex(
                'qXfer:features:read:target.xml:(.*),(.*)',
                pkt.decode(),
            )
            with open(self.xml_file, 'rb') as f:
                data = f.read()
            resp_data = data[off:off+length]
            if len(resp_data) < length:
                prefix = b'l'
            else:
                prefix = b'm'
            # Also populate self.registers from the static XML on the
            # first read so `g`/`p` have the register list they need.
            if not self.registers:
                try:
                    xml_regs = ET.fromstring(data).find('feature')
                    if xml_regs:
                        self.registers.extend(
                            reg.attrib for reg in xml_regs if reg.tag == 'reg'
                        )
                except ET.ParseError:
                    pass
            return prefix + resp_data

        if pkt[1:].startswith(b'fThreadInfo') is True:
            return b'm1'
        if pkt[1:].startswith(b'sThreadInfo') is True:
            return b'l'

        if pkt[1:].startswith(b'Rcmd') is True: # Monitor commands
            try:
                cmd = re.match('qRcmd,(.*)',pkt.decode())[1]
                cmd = binascii.a2b_hex(cmd) 
                l.debug(f'Receiced cmd: {cmd}')
                res = eval(cmd)
                
                self.send_packet(b'O' \
                            + binascii.b2a_hex(repr(res).encode()) \
                            + b'0a')
                return b'OK'
                
            except Exception as e:
                self.send_packet(b'O' + b'ERROR: '.hex().encode())
                
                if hasattr(e, 'msg'):
                    self.send_packet(b'O' \
                                + e.msg.encode().hex().encode() \
                                + b'0a')
                elif hasattr(e, 'args'):
                    self.send_packet(b'O' \
                                + e.args[0].encode().hex().encode() \
                                + b'0a')
                    
                return b'OK'

        return b''

    def multi_letter_cmd(self, pkt):
        if pkt[1:].startswith(b'vMustReplyEmpty') is True:
            return b''
        return b''

    def set_thread_op(self, pkt):
        return b'OK' # we don't implement threads yet

    def halt_reason(self, pkt):
        if self.target.state & TargetStates.STOPPED:
            return b'T05'  # SIGTRAP
        return b'S00'

    def read_registers(self, pkt):
        resp = ''
        for reg in self.registers:
            
            bitsize = int(reg['bitsize'])
            assert( bitsize % 8 == 0)
            r_len = int(bitsize / 8)
            r_val = self.target.read_register(reg['name'])
            if r_val is not None:
            #l.debug(f'{reg["name"]}, {r_val}, {r_len}')
                resp += r_val.to_bytes(r_len, 'little').hex()
            
        return resp.encode()
    
    def reg_write(self, pkt):
        idx = 1 # ignore the first char of pkt
        for reg in self.registers:
            bitsize = int(reg['bitsize'])
            r_len = int(bitsize / 8)
            r_val = pkt[idx: idx + r_len*2]
            r_raw = bytes.fromhex(r_val.decode())
            int_val =  int.from_bytes(r_raw, byteorder='little')

            self.target.write_register(reg['name'], int_val)
            idx += r_len*2
        return b'OK'


    def mem_read(self, pkt):
        try:
            addr, n = match_hex('m(.*),(.*)', pkt.decode())

            if self.do_forwarding is True:
                mr = self.avatar.get_memory_range(addr)
                if mr is not None and mr.forwarded is True:
                    val = mr.forwarded_to.read_memory(addr, n)
                    val = val.to_bytes(n, byteorder='little')
                    return binascii.b2a_hex(val)

            val = self.target.read_memory(addr, n, raw=True).hex()
            return val.encode()
            
        except Exception as e:
            l.warn(f'Error in mem_read: {e}')
            return b'E00'


    def mem_write(self, pkt):
        try:
            addr, n, val = match_hex('M(.*),(.*):(.*)', pkt.decode())
            raw_val = val.to_bytes(n, byteorder='big') # wtf :/

            if self.do_forwarding is True:
                mr = self.avatar.get_memory_range(addr)
                if mr is not None and mr.forwarded is True:
                    int_val = int.from_bytes(raw_val,byteorder='little')
                    mr.forwarded_to.write_memory(addr, n, int_val)
                    return b'OK'

            self.target.write_memory(addr, n, raw_val, raw=True)
            return b'OK'
            
        except Exception as e:
            l.warn(f'Error in mem_write: {e}')
            return b'E00'


    def read_single_reg(self, pkt):
        try:
            reg_num = int(pkt[1:].decode(), 16)
            if reg_num < len(self.registers):
                reg = self.registers[reg_num]
                bitsize = int(reg['bitsize'])
                r_len = bitsize // 8
                r_val = self.target.read_register(reg['name'])
                if r_val is not None:
                    return r_val.to_bytes(r_len, 'little').hex().encode()
            return b'E00'
        except Exception as e:
            l.warning(f'Error in read_single_reg: {e}')
            return b'E00'

    def write_single_reg(self, pkt):
        try:
            eq_pos = pkt.index(ord(b'='))
            reg_num = int(pkt[1:eq_pos].decode(), 16)
            if reg_num < len(self.registers):
                reg = self.registers[reg_num]
                bitsize = int(reg['bitsize'])
                r_len = bitsize // 8
                hex_val = pkt[eq_pos+1:]
                r_raw = bytes.fromhex(hex_val.decode())
                int_val = int.from_bytes(r_raw, byteorder='little')
                self.target.write_register(reg['name'], int_val)
                return b'OK'
            return b'E00'
        except Exception as e:
            l.warning(f'Error in write_single_reg: {e}')
            return b'E00'

    def cont(self, pkt):
        self.target.cont()
        self.running = True
        return None  # No response until target stops (GDB RSP run/stop model)

    def step(self, pkt):
        self.target.step()
        while not (self.target.state & TargetStates.STOPPED):
            sleep(0.0001)
        return b'T05'

    def insert_breakpoint(self, pkt):
        addr, kind = match_hex('Z0,(.*),(.*)', pkt.decode())
        bpno = self.target.set_breakpoint(addr)
        self.bps[bpno] = addr
        return b'OK'

    def remove_breakpoint(self, pkt):
        addr, kind = match_hex('z0,(.*),(.*)', pkt.decode())
        matches = []
        for n, a in self.bps.items():
            if a == addr:
                matches.append(n)
        if len(matches) == 0:
            l.warn(f'GDB tried to remove non existing bp for {addr}')
            l.info(self.bps)
            return b'E00'
        
        self.target.remove_breakpoint(n)
        self.bps.pop(n)
        return b'OK'

    def detach(self, pkt):
        l.info("Exiting GDB server")
        if not self.target.state & TargetStates.EXITED:
            for bpno in list(self.bps.keys()):
                self.target.remove_breakpoint(bpno)
            self.bps.clear()
            self.target.cont()
        self.running = False
        if self.conn._closed is False:
            self.send_packet(b'OK')
            self.conn.close()

        return None

    def kill(self, pkt):
        """
        Handle GDB's 'k' (kill) packet. cppdbg sends this when the user
        clicks Stop or Restart. Per RSP spec, 'k' has no reply — the
        server just terminates and tears down. We mirror the detach
        cleanup path (remove breakpoints, close the socket) and return
        None so the dispatcher doesn't try to send a response. The
        RSP server thread then exits its recv loop when conn is closed.
        """
        l.info("GDB client sent 'k' (kill); closing RSP connection")
        if not self.target.state & TargetStates.EXITED:
            for bpno in list(self.bps.keys()):
                try:
                    self.target.remove_breakpoint(bpno)
                except Exception as e:
                    l.debug("remove_breakpoint(%s) during kill failed: %s", bpno, e)
            self.bps.clear()
        self.running = False
        if self.conn._closed is False:
            try:
                self.conn.close()
            except Exception:
                pass
        return None

    ### Sending and receiving

    def send_packet(self, pkt):
        if type(pkt) == str:
            raise Exception("Packet require bytes, not strings")
        
        self.send_raw(b'$%b#%02x' % (pkt, chksum(pkt)))


    def send_raw(self, raw_bytes):
        l.debug(f'Sending data: {raw_bytes}')
        self.conn.send(raw_bytes)


    def check_breakpoint_hit(self):
        if self.target.state & TargetStates.STOPPED and self.running is True:
            # regs.pc can transiently return None when the target is
            # mid-transition (e.g. a HAL intercept just triggered and
            # avatar2 hasn't refreshed). Treat that as "no stable pc yet"
            # and try again on the next recv timeout instead of crashing
            # the whole RSP server thread.
            try:
                pc = self.target.regs.pc
            except Exception as e:
                l.debug("check_breakpoint_hit: regs.pc read failed: %s", e)
                return
            if pc is None:
                l.debug("check_breakpoint_hit: regs.pc returned None")
                return
            pc &= 0xFFFFFFFE
            if self.stop_filter and self.stop_filter(self.target, pc):
                return  # Suppressed — an external handler is dealing with it
            self.running = False
            self.send_packet(b'T05')


    def receive_packet(self):
        pkt_finished = False
        pkt_receiving = False
        while pkt_finished is False:
            try:
                c = self.conn.recv(1)
            except socket.timeout:
                if self._do_shutdown.isSet():
                    self.send_packet(b'S03')
                    self.conn.close()
                    return

                if self.target.state & TargetStates.EXITED:
                    self.send_packet(b'S03')
                    self.conn.close()
                    return
                self.check_breakpoint_hit()
                continue

            if c == b'\x03':
                if not self.target.state & TargetStates.STOPPED:
                    self.target.stop()
                self.send_packet(b'S02')
            elif c == b'$': # start of package
                pkt = b''
                pkt_receiving = True
            elif c == b'#': # end of package
                checksum = self.conn.recv(2)
                if int(checksum, 16) == chksum(pkt):
                    return pkt
                else:
                    raise Exception('Checksum Error')
                
            elif pkt_receiving == True:
                pkt += c


def spawn_gdb_server(self, target, port, do_forwarding=True, xml_file=None,
                     stop_filter=None):
    if xml_file is None:
        # default for now: use ARM
        xml_file = f'{dirname(__file__)}/gdb/arm-target.xml'

    server = GDBRSPServer(self, target, port, xml_file, do_forwarding)
    if stop_filter is not None:
        server.stop_filter = stop_filter
    server.start()
    self._gdb_servers.append(server)
    return server

def exit_server(avatar, watched_target):

    for s in avatar._gdb_servers:
        if s.target == watched_target:
            s.shutdown()
            avatar._gdb_servers.remove(s)

def load_plugin(avatar):
    avatar.spawn_gdb_server = MethodType(spawn_gdb_server, avatar)
    avatar.watchmen.add_watchman('TargetShutdown', when='before',
                                 callback=exit_server)

    avatar._gdb_servers = []
