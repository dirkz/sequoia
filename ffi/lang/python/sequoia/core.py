import io
from enum import Enum

from _sequoia import ffi, lib
from .error import Error
from .glue import SQObject, invoke

class IPCPolicy(Enum):
    External = lib.SQ_IPC_POLICY_EXTERNAL
    Internal = lib.SQ_IPC_POLICY_INTERNAL
    Robust = lib.SQ_IPC_POLICY_ROBUST

class Context(SQObject):
    _del = lib.sq_context_free
    def __init__(self,
                 home=None,
                 ipc_policy=IPCPolicy.Robust,
                 ephemeral=False):
        cfg = lib.sq_context_configure()
        if home:
            lib.sq_config_home(cfg, home.encode())
        lib.sq_config_ipc_policy(cfg, ipc_policy.value)
        if ephemeral:
            lib.sq_config_ephemeral(cfg)
        err = ffi.new("pgp_error_t[1]")
        o = lib.sq_config_build(cfg, err)
        if o == ffi.NULL:
            raise Error._from(err[0])
        super(Context, self).__init__(o)

class AbstractReader(SQObject, io.RawIOBase):
    _del = lib.pgp_reader_free

    def readable(self):
        return True
    def writable(self):
        return False

    def readinto(self, buf):
        return invoke(
            lib.pgp_reader_read,
            self.ref(),
            ffi.cast("uint8_t *", ffi.from_buffer(buf)),
            len(buf))

    def close(self):
        self._delete()

    # Implement the context manager protocol.
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()
        return False

class Reader(AbstractReader):
    @classmethod
    def open(cls, ctx, filename):
        return Reader(
            invoke(lib.pgp_reader_from_file,
                   filename.encode()),
            context=ctx)

    @classmethod
    def from_fd(cls, ctx, fd):
        return Reader(lib.pgp_reader_from_fd(fd),
                      context=ctx)

    @classmethod
    def from_bytes(cls, ctx, buf):
        return Reader(
            lib.pgp_reader_from_bytes(
                ffi.cast("uint8_t *", ffi.from_buffer(buf)), len(buf)),
            context=ctx)

class AbstractWriter(SQObject, io.RawIOBase):
    _del = lib.pgp_writer_free

    def readable(self):
        return False
    def writable(self):
        return True

    def write(self, buf):
        return invoke(
            lib.pgp_writer_write,
            self.ref(),
            ffi.cast("const uint8_t *", ffi.from_buffer(buf)),
            len(buf))

    def close(self):
        self._delete()

    # Implement the context manager protocol.
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()
        return False

class Writer(AbstractWriter):
    @classmethod
    def open(cls, ctx, filename):
        return Writer(
            invoke(lib.pgp_writer_from_file,
                   filename.encode()),
            context=ctx)

    @classmethod
    def from_fd(cls, ctx, fd):
        return Writer(lib.pgp_writer_from_fd(fd),
                      context=ctx)

    @classmethod
    def from_bytes(cls, ctx, buf):
        return Writer(
            lib.pgp_writer_from_bytes(
                ffi.cast("uint8_t *", ffi.from_buffer(buf)), len(buf)),
            context=ctx)
