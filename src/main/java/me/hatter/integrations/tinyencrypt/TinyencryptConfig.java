package me.hatter.integrations.tinyencrypt;

/**
 * tinyencrypt config
 *
 * @author hatterjiang
 */
public class TinyencryptConfig {
    /**
     * REQUIRED, tinyencrypt key ID
     */
    private String keyId;
    /**
     * OPTIONAL, tinyencrypt command path, default "gpg"
     */
    private String tinyencryptCommand;
    /**
     * OPTIONAL, Encrypt key base path, default "~/.config/cryptomator/tinyencrypt_keys/"
     */
    private String encryptKeyBasePath;

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
}
