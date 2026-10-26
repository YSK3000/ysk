"""Process lifetime lock for a single real monitor per data directory."""
from contextlib import contextmanager
import fcntl
from kekkai import paths


@contextmanager
def single_monitor():
    with paths.sub("monitor.lock").open("a") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
