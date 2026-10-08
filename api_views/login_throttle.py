import math
import threading
import time
from collections import deque

'''
 Brute force protection for the login endpoint.
 Failed logins are counted per client address and username, and per client address across all usernames
 (password spraying). Once a limit is reached every login attempt it covers is refused, the right password
 included, until the oldest counted failure is older than the window. Successful logins are not counted.
'''
MAX_FAILURES_PER_USER = 5
MAX_FAILURES_PER_CLIENT = 30
WINDOW_SECONDS = 300
# drop expired entries once this many keys are tracked, so random usernames can't grow memory forever
PRUNE_THRESHOLD = 10000

_lock = threading.Lock()
_failures = {}


def _limits(client, username):
    return ((('user', client, username), MAX_FAILURES_PER_USER),
            (('client', client), MAX_FAILURES_PER_CLIENT))


def _recent(key, now):
    attempts = _failures.get(key)
    if attempts is None:
        return None
    while attempts and now - attempts[0] >= WINDOW_SECONDS:
        attempts.popleft()
    if not attempts:
        del _failures[key]
        return None
    return attempts


def retry_after(client, username):
    """Seconds until a login may be attempted again, or 0 when it is allowed now."""
    now = time.monotonic()
    wait = 0
    with _lock:
        for key, limit in _limits(client, username):
            attempts = _recent(key, now)
            if attempts and len(attempts) >= limit:
                # the attempt that has to expire before the count drops below the limit
                expires = attempts[len(attempts) - limit] + WINDOW_SECONDS
                wait = max(wait, math.ceil(expires - now))
    return wait


def record_failure(client, username):
    now = time.monotonic()
    with _lock:
        if len(_failures) > PRUNE_THRESHOLD:
            for key in list(_failures):
                _recent(key, now)
        for key, _ in _limits(client, username):
            _failures.setdefault(key, deque()).append(now)


def record_success(client, username):
    with _lock:
        _failures.pop(('user', client, username), None)
