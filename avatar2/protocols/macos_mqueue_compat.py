"""
macOS compatibility shim for posix_ipc.MessageQueue.

macOS does not support POSIX message queues. This module provides a drop-in
replacement backed by named FIFOs with a 4-byte little-endian length prefix
to preserve message boundaries — matching the framing used by the C-side
macos_mqueue.h shim in avatar-qemu.

Interface matches what remote_memory.py uses:
    mq = MessageQueue(name, flags, max_message_size=N)
    data, priority = mq.receive(timeout=None)
    mq.send(message_bytes)
    mq.close()
    mq.unlink()
"""

import os
import select
import struct
import errno
import fcntl


def _mq_to_path(name):
    """Map a POSIX mqueue name like '/avatar_rx' to a FIFO path."""
    return '/tmp/mq_{}'.format(name.lstrip('/'))


class MessageQueue:
    """Named-FIFO message queue with 4-byte LE length-prefix framing."""

    def __init__(self, name, flags=0, mode=0o600, max_messages=10,
                 max_message_size=128, read=True, write=True):
        self._name = name
        self._path = _mq_to_path(name)
        self._fd = -1

        if flags & os.O_CREAT:
            try:
                os.mkfifo(self._path, mode)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise

        # O_RDWR avoids blocking until the peer connects.
        self._fd = os.open(self._path, os.O_RDWR)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_exactly(self, n, timeout):
        """Read exactly *n* bytes, blocking up to *timeout* seconds."""
        data = b''
        remaining = n
        deadline = None
        if timeout is not None:
            import time
            deadline = time.monotonic() + timeout

        while remaining > 0:
            if deadline is not None:
                left = deadline - __import__('time').monotonic()
                if left <= 0:
                    raise TimeoutError("mqueue receive timed out")
                r, _, _ = select.select([self._fd], [], [], left)
                if not r:
                    raise TimeoutError("mqueue receive timed out")
            chunk = os.read(self._fd, remaining)
            if not chunk:
                raise OSError("FIFO closed unexpectedly")
            data += chunk
            remaining -= len(chunk)
        return data

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def receive(self, timeout=None):
        """
        Return (message_bytes, priority).

        Reads the 4-byte LE length prefix, then reads exactly that many bytes.
        Blocks up to *timeout* seconds (None = block forever).
        """
        hdr = self._read_exactly(4, timeout)
        payload_len = struct.unpack('<I', hdr)[0]
        payload = self._read_exactly(payload_len, timeout)
        return payload, 0

    def send(self, message, timeout=None, priority=0):
        """Write *message* with a 4-byte LE length prefix."""
        framed = struct.pack('<I', len(message)) + message
        os.write(self._fd, framed)

    def close(self):
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def unlink(self):
        """Remove the FIFO from the filesystem (fd remains valid if open)."""
        try:
            os.unlink(self._path)
        except OSError:
            pass


class ExistentialError(OSError):
    """Mirrors posix_ipc.ExistentialError."""
    pass
