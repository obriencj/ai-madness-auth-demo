"""
Hybrid keytab caching system for GSSAPI authentication.

This module implements a three-tier caching strategy:
- L1: In-memory cache (fastest, highest security risk)
- L2: Redis cache (medium speed, medium security)
- L3: Database encrypted (slowest, highest security)

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import time
import tempfile
import os
from typing import Optional, Dict, Any
from .crypto import KeytabEncryption


class KeytabCache:
    """Hybrid keytab caching system."""
    
    def __init__(self, max_memory_size=50, memory_ttl_hours=4, redis_ttl_hours=24):
        """
        Initialize the keytab cache.
        
        Args:
            max_memory_size: Maximum number of keytabs in memory cache
            memory_ttl_hours: TTL for memory cache entries in hours
            redis_ttl_hours: TTL for Redis cache entries in hours
        """
        self.max_memory_size = max_memory_size
        self.memory_ttl_hours = memory_ttl_hours
        self.redis_ttl_hours = redis_ttl_hours
        
        # L1: In-memory cache
        self.memory_cache: Dict[int, Dict[str, Any]] = {}
        
        # L2: Redis cache (optional)
        self.redis_client = None
        self._init_redis()
        
        # Encryption for Redis cache
        self.crypto = KeytabEncryption()
    
    def _init_redis(self):
        """Initialize Redis connection if available."""
        try:
            import redis
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
            self.redis_client = redis.from_url(redis_url)
            # Test connection
            self.redis_client.ping()
        except Exception as e:
            print(f"Redis not available for keytab caching: {e}")
            self.redis_client = None
    
    def get_keytab(self, realm_id: int, encrypted_data: bytes, iv: bytes, salt: bytes) -> bytes:
        """
        Get decrypted keytab data, using cache if available.
        
        Args:
            realm_id: ID of the realm
            encrypted_data: Encrypted keytab data from database
            iv: Initialization vector
            salt: Salt for key derivation
            
        Returns:
            Decrypted keytab data
        """
        # Try L1 cache (memory)
        keytab_data = self._get_from_memory(realm_id)
        if keytab_data:
            return keytab_data
        
        # Try L2 cache (Redis)
        keytab_data = self._get_from_redis(realm_id)
        if keytab_data:
            # Store in L1 cache for faster future access
            self._store_in_memory(realm_id, keytab_data)
            return keytab_data
        
        # L3 cache miss - decrypt from database
        keytab_data = self._decrypt_from_database(encrypted_data, iv, salt)
        
        # Store in both caches
        self._store_in_memory(realm_id, keytab_data)
        self._store_in_redis(realm_id, keytab_data)
        
        return keytab_data
    
    def _get_from_memory(self, realm_id: int) -> Optional[bytes]:
        """Get keytab from memory cache."""
        if realm_id not in self.memory_cache:
            return None
        
        entry = self.memory_cache[realm_id]
        if self._is_memory_expired(entry):
            del self.memory_cache[realm_id]
            return None
        
        # Update access statistics
        entry['last_used'] = time.time()
        entry['access_count'] += 1
        
        return entry['keytab_data']
    
    def _get_from_redis(self, realm_id: int) -> Optional[bytes]:
        """Get keytab from Redis cache."""
        if not self.redis_client:
            return None
        
        try:
            cache_key = f"keytab:{realm_id}"
            cached_data = self.redis_client.get(cache_key)
            
            if cached_data:
                # Decrypt cached data (Redis cache is also encrypted)
                # For simplicity, we'll use a different encryption key for Redis
                # In production, you might want to use a separate Redis encryption key
                return self._decrypt_redis_cache(cached_data)
            
            return None
        except Exception as e:
            print(f"Error retrieving from Redis cache: {e}")
            return None
    
    def _store_in_memory(self, realm_id: int, keytab_data: bytes):
        """Store keytab in memory cache."""
        # Evict old entries if cache is full
        if len(self.memory_cache) >= self.max_memory_size:
            self._evict_oldest_memory()
        
        self.memory_cache[realm_id] = {
            'keytab_data': keytab_data,
            'created_at': time.time(),
            'last_used': time.time(),
            'access_count': 1
        }
    
    def _store_in_redis(self, realm_id: int, keytab_data: bytes):
        """Store keytab in Redis cache."""
        if not self.redis_client:
            return
        
        try:
            cache_key = f"keytab:{realm_id}"
            # Encrypt data before storing in Redis
            encrypted_cache_data = self._encrypt_redis_cache(keytab_data)
            
            # Store with TTL
            self.redis_client.setex(
                cache_key,
                self.redis_ttl_hours * 3600,  # Convert hours to seconds
                encrypted_cache_data
            )
        except Exception as e:
            print(f"Error storing in Redis cache: {e}")
    
    def _decrypt_from_database(self, encrypted_data: bytes, iv: bytes, salt: bytes) -> bytes:
        """Decrypt keytab data from database."""
        return self.crypto.decrypt_keytab(encrypted_data, iv, salt)
    
    def _encrypt_redis_cache(self, keytab_data: bytes) -> bytes:
        """Encrypt data for Redis cache storage."""
        # Use a different encryption approach for Redis cache
        # This could be a simpler encryption or a different key
        # For now, we'll use the same encryption but with a different salt
        result = self.crypto.encrypt_keytab(keytab_data)
        # Return a combined format: salt + iv + encrypted_data
        return result['salt'] + result['iv'] + result['encrypted_data']
    
    def _decrypt_redis_cache(self, cached_data: bytes) -> bytes:
        """Decrypt data from Redis cache."""
        try:
            # Extract salt, iv, and encrypted data
            salt = cached_data[:16]
            iv = cached_data[16:28]
            encrypted_data = cached_data[28:]
            
            return self.crypto.decrypt_keytab(encrypted_data, iv, salt)
        except Exception as e:
            print(f"Error decrypting Redis cache data: {e}")
            return None
    
    def _is_memory_expired(self, entry: Dict[str, Any]) -> bool:
        """Check if memory cache entry is expired."""
        age_hours = (time.time() - entry['created_at']) / 3600
        return age_hours > self.memory_ttl_hours
    
    def _evict_oldest_memory(self):
        """Evict the oldest memory cache entry."""
        if not self.memory_cache:
            return
        
        # Find oldest entry
        oldest_realm_id = min(
            self.memory_cache.keys(),
            key=lambda rid: self.memory_cache[rid]['last_used']
        )
        
        del self.memory_cache[oldest_realm_id]
    
    def invalidate_realm(self, realm_id: int):
        """Invalidate cache entries for a specific realm."""
        # Remove from memory cache
        if realm_id in self.memory_cache:
            del self.memory_cache[realm_id]
        
        # Remove from Redis cache
        if self.redis_client:
            try:
                cache_key = f"keytab:{realm_id}"
                self.redis_client.delete(cache_key)
            except Exception as e:
                print(f"Error invalidating Redis cache: {e}")
    
    def clear_all(self):
        """Clear all caches."""
        self.memory_cache.clear()
        
        if self.redis_client:
            try:
                # Delete all keytab cache keys
                keys = self.redis_client.keys("keytab:*")
                if keys:
                    self.redis_client.delete(*keys)
            except Exception as e:
                print(f"Error clearing Redis cache: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        stats = {
            'memory_cache': {
                'size': len(self.memory_cache),
                'max_size': self.max_memory_size,
                'ttl_hours': self.memory_ttl_hours
            },
            'redis_cache': {
                'available': self.redis_client is not None,
                'ttl_hours': self.redis_ttl_hours
            }
        }
        
        if self.redis_client:
            try:
                keys = self.redis_client.keys("keytab:*")
                stats['redis_cache']['size'] = len(keys)
            except Exception:
                stats['redis_cache']['size'] = 0
        
        return stats


# Global cache instance
_keytab_cache = None


def get_keytab_cache() -> KeytabCache:
    """Get the global keytab cache instance."""
    global _keytab_cache
    if _keytab_cache is None:
        _keytab_cache = KeytabCache()
    return _keytab_cache


# The end.
