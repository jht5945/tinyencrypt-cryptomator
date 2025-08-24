package me.hatter.integrations.tinyencrypt;

/**
 * tinyencrypt config
 *
 * @author hatterjiang
 */
public class TinyencryptConfig2 {
    /**
     * REQUIRED, tinyencrypt key ID
     */
    private String keyId;
    /**
     * OPTIONAL, tinyencrypt command path, default "tinyencrypt"
     */
    private String tinyencryptCommand;
    /**
     * OPTIONAL, Encrypt key base path, default "~/.config/cryptomator/tinyencrypt_keys/"
     */
    private String encryptKeyBasePath;
    /**
     * OPTIONAL, PBDKF encryption key
     */
    private Boolean enablePbkdfEncryptionPassword;

    /**
     * OPTIONAL, vault password cache
     */
    private Boolean enableVaultPasswordCache;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getTinyencryptCommand() {
        return tinyencryptCommand;
    }

    public void setTinyencryptCommand(String tinyencryptCommand) {
        this.tinyencryptCommand = tinyencryptCommand;
    }

    public String getEncryptKeyBasePath() {
        return encryptKeyBasePath;
    }

    public void setEncryptKeyBasePath(String encryptKeyBasePath) {
        this.encryptKeyBasePath = encryptKeyBasePath;
    }

    public Boolean getEnablePbkdfEncryptionPassword() {
        return enablePbkdfEncryptionPassword;
    }

    public void setEnablePbkdfEncryptionPassword(Boolean enablePbkdfEncryptionPassword) {
        this.enablePbkdfEncryptionPassword = enablePbkdfEncryptionPassword;
    }

    public Boolean getEnableVaultPasswordCache() {
        return enableVaultPasswordCache;
    }

    public void setEnableVaultPasswordCache(Boolean enableVaultPasswordCache) {
        this.enableVaultPasswordCache = enableVaultPasswordCache;
    }
}
