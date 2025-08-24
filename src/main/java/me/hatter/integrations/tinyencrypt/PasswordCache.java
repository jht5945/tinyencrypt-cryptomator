package me.hatter.integrations.tinyencrypt;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class PasswordCache {
    private final ConcurrentMap<String, CachedPasswordWithTime> passwordCacheMap = new ConcurrentHashMap<>();
    private final long passwordCacheTimeMillis;

    public PasswordCache(long passwordCacheTimeMillis) {
        this.passwordCacheTimeMillis = passwordCacheTimeMillis;
    }

    private static class CachedPasswordWithTime {
        private String password;
        private long timestamp;
    }

    public void removePassword(TinyencryptConfig2 tinyEncryptConfig, String key) {
        passwordCacheMap.remove(key);
    }

    public void putPassword(TinyencryptConfig2 tinyencryptConfig, String key, String password) {
        final CachedPasswordWithTime cachedPasswordWithTime = new CachedPasswordWithTime();
        cachedPasswordWithTime.password = password;
        cachedPasswordWithTime.timestamp = System.currentTimeMillis();
        passwordCacheMap.put(key, cachedPasswordWithTime);
    }

    public String getPassword(TinyencryptConfig2 tinyencryptConfig, String key) {
        final CachedPasswordWithTime cachedPasswordWithTime = passwordCacheMap.get(key);
        if (cachedPasswordWithTime == null) {
            return null;
        }
        if ((System.currentTimeMillis() - cachedPasswordWithTime.timestamp) > passwordCacheTimeMillis) {
            passwordCacheMap.remove(key);
            return null;
        }
        cachedPasswordWithTime.timestamp = System.currentTimeMillis();
        return cachedPasswordWithTime.password;
    }
}
