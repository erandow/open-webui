import time
from typing import Optional, Dict
from open_webui.env import REDIS_KEY_PREFIX


class RateLimiter:
    """
    General-purpose rate limiter using Redis with a rolling window strategy.
    Falls back to in-memory storage if Redis is not available.
    """

    # In-memory fallback storage
    _memory_store: Dict[str, Dict[int, int]] = {}

    def __init__(
        self,
        redis_client,
        limit: int,
        window: int,
        bucket_size: int = 60,
        enabled: bool = True,
    ):
        """
        :param redis_client: Redis client instance or None
        :param limit: Max allowed events in the window
        :param window: Time window in seconds
        :param bucket_size: Bucket resolution
        :param enabled: Turn on/off rate limiting globally
        """
        self.r = redis_client
        self.limit = limit
        self.window = window
        self.bucket_size = bucket_size
        self.num_buckets = window // bucket_size
        self.enabled = enabled

    def _bucket_key(self, key: str, bucket_index: int) -> str:
        return f"{REDIS_KEY_PREFIX}:ratelimit:{key.lower()}:{bucket_index}"

    def _current_bucket(self) -> int:
        return int(time.time()) // self.bucket_size

    def _redis_available(self) -> bool:
        return self.r is not None

    def is_limited(self, key: str) -> bool:
        """
        Main rate-limit check.
        Gracefully handles missing or failing Redis.
        """
        if not self.enabled:
            return False

        if self._redis_available():
            try:
                return self._is_limited_redis(key)
            except Exception:
                return self._is_limited_memory(key)
        else:
            return self._is_limited_memory(key)

    def get_count(self, key: str) -> int:
        if not self.enabled:
            return 0

        if self._redis_available():
            try:
                return self._get_count_redis(key)
            except Exception:
                return self._get_count_memory(key)
        else:
            return self._get_count_memory(key)

    def remaining(self, key: str) -> int:
        used = self.get_count(key)
        return max(0, self.limit - used)

    def _is_limited_redis(self, key: str) -> bool:
        now_bucket = self._current_bucket()
        bucket_key = self._bucket_key(key, now_bucket)

        attempts = self.r.incr(bucket_key)
        if attempts == 1:
            self.r.expire(bucket_key, self.window + self.bucket_size)

        # Collect buckets
        buckets = [
            self._bucket_key(key, now_bucket - i) for i in range(self.num_buckets + 1)
        ]

        counts = self.r.mget(buckets)
        total = sum(int(c) for c in counts if c)

        return total > self.limit

    def _get_count_redis(self, key: str) -> int:
        now_bucket = self._current_bucket()
        buckets = [
            self._bucket_key(key, now_bucket - i) for i in range(self.num_buckets + 1)
        ]
        counts = self.r.mget(buckets)
        return sum(int(c) for c in counts if c)

    def _is_limited_memory(self, key: str) -> bool:
        now_bucket = self._current_bucket()

        # Init storage
        if key not in self._memory_store:
            self._memory_store[key] = {}

        store = self._memory_store[key]

        # Increment bucket
        store[now_bucket] = store.get(now_bucket, 0) + 1

        # Drop expired buckets
        min_bucket = now_bucket - self.num_buckets
        expired = [b for b in store if b < min_bucket]
        for b in expired:
            del store[b]

        # Count totals
        total = sum(store.values())
        return total > self.limit

    def _get_count_memory(self, key: str) -> int:
        now_bucket = self._current_bucket()
        if key not in self._memory_store:
            return 0

        store = self._memory_store[key]
        min_bucket = now_bucket - self.num_buckets

        # Remove expired
        expired = [b for b in store if b < min_bucket]
        for b in expired:
            del store[b]

        return sum(store.values())


class FailedLoginTracker:
    """
    Tracks failed login attempts per key (e.g. email) and enforces lockout
    after max_attempts failures. Uses Redis with in-memory fallback.
    """

    _memory_store: Dict[str, Dict[str, int]] = {}  # key -> {count, lock_until_ts}

    def __init__(
        self,
        redis_client,
        max_attempts: int = 5,
        lockout_seconds: int = 900,
        enabled: bool = True,
    ):
        """
        :param redis_client: Redis client or None
        :param max_attempts: Number of failed attempts before lockout
        :param lockout_seconds: How long to lock (seconds) after max_attempts
        :param enabled: Turn on/off globally
        """
        self.r = redis_client
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.enabled = enabled

    def _key(self, key: str) -> str:
        return f"{REDIS_KEY_PREFIX}:failed_login:{key.lower()}"

    def _redis_available(self) -> bool:
        return self.r is not None

    def is_locked(self, key: str) -> bool:
        """True if this key is currently locked due to too many failed attempts."""
        if not self.enabled:
            return False
        if self._redis_available():
            try:
                return self._is_locked_redis(key)
            except Exception:
                return self._is_locked_memory(key)
        return self._is_locked_memory(key)

    def record_failed(self, key: str) -> None:
        """Record a failed login attempt; may trigger lockout."""
        if not self.enabled:
            return
        if self._redis_available():
            try:
                self._record_failed_redis(key)
                return
            except Exception:
                pass
        
        self._record_failed_memory(key)

    def clear(self, key: str) -> None:
        """Clear failed attempts (call on successful login)."""
        if not self.enabled:
            return
        k = self._key(key)
        if self._redis_available():
            try:
                self.r.delete(k)
                return
            except Exception:
                pass
        key_lower = key.lower()
        if key_lower in self._memory_store:
            del self._memory_store[key_lower]

    def _is_locked_redis(self, key: str) -> bool:
        k = self._key(key)
        count = self.r.get(k)
        if count is None:
            return False
        return int(count) >= self.max_attempts

    def _record_failed_redis(self, key: str) -> None:
        k = self._key(key)
        count = self.r.incr(k)
        if count == 1:
            self.r.expire(k, self.lockout_seconds)
        elif count >= self.max_attempts:
            self.r.expire(k, self.lockout_seconds)

    def _is_locked_memory(self, key: str) -> bool:
        key_lower = key.lower()
        if key_lower not in self._memory_store:
            return False
        now = int(time.time())
        entry = self._memory_store[key_lower]
        lock_until_ts = entry.get("lock_until_ts", 0)
        # Only clear when a lockout was set and has expired (don't clear when lock_until_ts is 0)
        if lock_until_ts > 0 and now >= lock_until_ts:
            del self._memory_store[key_lower]
            return False
        return entry.get("count", 0) >= self.max_attempts

    def _record_failed_memory(self, key: str) -> None:
        key_lower = key.lower()
        now = int(time.time())
        if key_lower not in self._memory_store:
            self._memory_store[key_lower] = {"count": 0, "lock_until_ts": 0}
        entry = self._memory_store[key_lower]

        # Only reset count when a previous lockout has expired (don't reset when lock_until_ts is 0)
        if entry["lock_until_ts"] > 0 and now >= entry["lock_until_ts"]:
            entry["count"] = 0
            entry["lock_until_ts"] = 0
        entry["count"] = entry.get("count", 0) + 1
        if entry["count"] >= self.max_attempts:
            entry["lock_until_ts"] = now + self.lockout_seconds
