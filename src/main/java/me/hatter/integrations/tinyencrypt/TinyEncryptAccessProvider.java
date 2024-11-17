package me.hatter.integrations.tinyencrypt;

import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.cryptomator.integrations.keychain.KeychainAccessProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author hatterjiang
 */
public class TinyEncryptAccessProvider implements KeychainAccessProvider {

    private static final Logger LOG = LoggerFactory.getLogger(TinyEncryptAccessProvider.class);

    private TinyencryptConfig tinyencryptConfig;

    public TinyEncryptAccessProvider() {
        try {
            tinyencryptConfig = Utils.loadTinyencryptConfig();
            if (!Utils.checkTinyencryptReady(tinyencryptConfig)) {
                LOG.error("Check tinyencrypt command failed");
                tinyencryptConfig = null;
            }
        } catch (KeychainAccessException e) {
            tinyencryptConfig = null;
            LOG.error("Load tinyencrypt config failed", e);
        }
    }

    @Override
    public String displayName() {
        return "TinyEncrypt";
    }

    @Override
    public boolean isSupported() {
        return tinyencryptConfig != null;
    }

    @Override
    public boolean isLocked() {
        // No lock status
        return false;
    }

    @Override
    public void storePassphrase(String vault, CharSequence password) throws KeychainAccessException {
        storePassphrase(vault, "Vault", password);
    }

    @Override
    public void storePassphrase(String vault, String name, CharSequence password) throws KeychainAccessException {
        LOG.info("Store password for: " + vault + " / " + name);
        Utils.storePassword(tinyencryptConfig, vault, name, password);
    }

    @Override
    public char[] loadPassphrase(String vault) throws KeychainAccessException {
        final String password = Utils.loadPassword(tinyencryptConfig, vault);
        return password.toCharArray();
    }

    @Override
    public void deletePassphrase(String vault) throws KeychainAccessException {
        LOG.info("Delete password for: " + vault);
        Utils.deletePassword(tinyencryptConfig, vault);
    }

    @Override
    public void changePassphrase(String vault, CharSequence password) throws KeychainAccessException {
        LOG.info("Change password for: " + vault);
        changePassphrase(vault, "Vault", password);
    }

    @Override
    public void changePassphrase(String vault, String name, CharSequence password) throws KeychainAccessException {
        LOG.info("Change password for: " + vault + " / " + name);
        Utils.storePassword(tinyencryptConfig, vault, name, password);
    }
}
