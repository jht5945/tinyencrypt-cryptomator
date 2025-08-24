package me.hatter.integrations.tinyencrypt;

import com.google.gson.Gson;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.cryptomator.integrations.keychain.KeychainAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * @author hatterjiang
 */
public class Utils {
    private static final Logger LOG = LoggerFactory.getLogger(Utils.class);
    private static final String DEFAULT_TINY_ENCRYPT_COMMAND = "tinyencrypt";
    private static final String USER_HOME = System.getProperty("user.home");
    private static final File TINYENCRYPT_CONFIG_FILE1 = new File("/etc/cryptomator/tinyencrypt_config.json");
    private static final File TINYENCRYPT_CONFIG_FILE2 = new File(USER_HOME, ".config/cryptomator/tinyencrypt_config.json");
    private static final File DEFAULT_ENCRYPTION_KEY_BASE_PATH = new File(USER_HOME, ".config/cryptomator/tinyencrypt_keys/");

    private static final PasswordCache PBKDF_PASSWORD_CACHE_MAP = new PasswordCache(TimeUnit.HOURS.toMillis(1));
    private static final PasswordCache VAULT_PASSWORD_CACHE_MAP = new PasswordCache(TimeUnit.HOURS.toMillis(1));

    public static boolean isCheckPassphraseStored() {
        final StackTraceElement stack = getCallerStackTrace();
        if (stack != null) {
            return "isPassphraseStored".equals(stack.getMethodName());
        }
        return false;
    }

    public static StackTraceElement getCallerStackTrace() {
        // org.cryptomator.common.keychain.KeychainManager :: isPassphraseStored
        final StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
        for (int i = 0; i < stackTraceElements.length; i++) {
            final StackTraceElement stack = stackTraceElements[i];
            if ("org.cryptomator.common.keychain.KeychainManager".equals(stack.getClassName())) {
                return stack;
            }
        }
        return null;
    }

    public static boolean checkTinyencryptReady(TinyEncryptConfig tinyencryptConfig) {
        if (tinyencryptConfig == null) {
            return false;
        }
        try {
            final UtilsCommandResult versionResult = runTinyencrypt(tinyencryptConfig, null, "version");
            if (versionResult.getExitValue() == 0) {
                return true;
            }
            LOG.warn("Check tinyencrypt not success: " + versionResult);
            return false;
        } catch (KeychainAccessException e) {
            LOG.warn("Check tinyencrypt failed", e);
            return false;
        }
    }

    public static TinyEncryptConfig loadTinyencryptConfig() throws KeychainAccessException {
        final File configFile = getTinyencryptConfigFile();
        final String configJson = readFile(configFile);
        final TinyEncryptConfig tinyencryptConfig;
        try {
            tinyencryptConfig = new Gson().fromJson(configJson, TinyEncryptConfig.class);
        } catch (Exception e) {
            throw new KeychainAccessException("Parse tinyencrypt config file: " + configFile + " failed", e);
        }
        if (StringUtils.isEmpty(tinyencryptConfig.getKeyId())) {
            throw new KeychainAccessException("tinyencrypt key ID cannot be empty");
        }
        return tinyencryptConfig;
    }

    public static void deletePassword(TinyEncryptConfig tinyencryptConfig, String vault) {
        final File keyFile = getKeyFile(tinyencryptConfig, vault);
        if (keyFile.exists() && keyFile.isFile()) {
            keyFile.delete();
        }
        PBKDF_PASSWORD_CACHE_MAP.removePassword(tinyencryptConfig, vault);
        VAULT_PASSWORD_CACHE_MAP.removePassword(tinyencryptConfig, vault);
    }

    public static String loadPassword(TinyEncryptConfig tinyencryptConfig, String vault) throws KeychainAccessException {
        final String cachedVaultPassword = VAULT_PASSWORD_CACHE_MAP.getPassword(tinyencryptConfig, vault);
        if (BooleanUtils.isTrue(tinyencryptConfig.getEnableVaultPasswordCache()) && (cachedVaultPassword != null)) {
            return cachedVaultPassword;
        }
        final File keyFile = getKeyFile(tinyencryptConfig, vault);
        if (isCheckPassphraseStored()) {
            LOG.info("Check passphrase stored: " + vault + ", exists: " + keyFile.exists());
            if (keyFile.exists()) {
                // this is only for check passphrase stored
                return "123456";
            }
        }
        if (!keyFile.isFile()) {
            throw new KeychainAccessException("Password key file: " + keyFile + " not found");
        }
        final String encryptedKey = readFile(keyFile);
        final String vaultPassword = decrypt(tinyencryptConfig, vault, encryptedKey);
        if (BooleanUtils.isTrue(tinyencryptConfig.getEnableVaultPasswordCache())) {
            LOG.info("Store vault password to cache");
            VAULT_PASSWORD_CACHE_MAP.putPassword(tinyencryptConfig, vault, vaultPassword);
        }
        return vaultPassword;
    }

    public static void storePassword(TinyEncryptConfig tinyencryptConfig, String vault, String name, CharSequence password) throws KeychainAccessException {
        if (BooleanUtils.isTrue(tinyencryptConfig.getEnableVaultPasswordCache())) {
            LOG.info("Store vault password to cache");
            VAULT_PASSWORD_CACHE_MAP.putPassword(tinyencryptConfig, vault, password.toString());
        }
        final String encryptedPassword = encrypt(tinyencryptConfig, vault, password.toString(), name);
        final File keyFile = getKeyFile(tinyencryptConfig, vault);
        writeFile(keyFile, encryptedPassword);
    }

    private static File getKeyFile(TinyEncryptConfig tinyencryptConfig, String vault) {
        final StringBuilder sb = new StringBuilder(vault.length());
        for (char c : vault.toCharArray()) {
            if ((c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || (c == '-' || c == '.')) {
                sb.append(c);
            } else if (c == '_') {
                sb.append("__");
            } else {
                sb.append('_');
                final String hex = Integer.toHexString(c);
                if (hex.length() % 2 != 0) {
                    sb.append('0');
                }
                sb.append(hex);
            }
        }
        return new File(getEncryptKeyBasePath(tinyencryptConfig), sb.toString());
    }

    private static String readFile(File file) throws KeychainAccessException {
        final StringBuilder sb = new StringBuilder((int) file.length());
        try (final BufferedReader reader = new BufferedReader(new FileReader(file, StandardCharsets.UTF_8))) {
            for (int b; ((b = reader.read()) != -1); ) {
                sb.append((char) b);
            }
            return sb.toString();
        } catch (IOException e) {
            throw new KeychainAccessException("Read file: " + file + " failed", e);
        }
    }

    private static void writeFile(File file, String content) throws KeychainAccessException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new KeychainAccessException("Write file: " + file + " failed", e);
        }
    }

    private static String decrypt(TinyEncryptConfig tinyencryptConfig, String vault, String input) throws KeychainAccessException {
        List<String> arguments = new ArrayList<>();
        arguments.add("simple-decrypt");
        arguments.add("--value-stdin");
        arguments.add("--pin");
        arguments.add("#INPUT#");

        boolean inputNewPassword = false;
        String cachedPassword = PBKDF_PASSWORD_CACHE_MAP.getPassword(tinyencryptConfig, vault);
        if (StringUtils.isNotEmpty(cachedPassword)) {
            arguments.add("--password");
            arguments.add(cachedPassword);
        } else {
            inputNewPassword = true;
            arguments.add("--outputs-password");
        }

        final UtilsCommandResult decryptResult = runTinyencrypt(
                tinyencryptConfig,
                input.getBytes(StandardCharsets.UTF_8),
                arguments.toArray(new String[0])
        );
        if (decryptResult.getExitValue() != 0) {
            throw new KeychainAccessException("tinyencrypt decrypt failed: " + decryptResult);
        }
        String stdout = new String(decryptResult.getStdout(), StandardCharsets.UTF_8);
        stdout = stdout.lines().filter(ln -> !ln.startsWith("[INFO ]")).collect(Collectors.joining());
        TinyEncryptResult result = new Gson().fromJson(stdout, TinyEncryptResult.class);
        if (inputNewPassword && StringUtils.isNotEmpty(result.getPassword())) {
            LOG.info("Store PBKDF password to cache");
            PBKDF_PASSWORD_CACHE_MAP.putPassword(tinyencryptConfig, vault, result.getPassword());
        }
        return result.getResult();
    }

    private static String encrypt(TinyEncryptConfig tinyencryptConfig, String vault, String input, String name) throws KeychainAccessException {
        List<String> arguments = new ArrayList<>();
        arguments.add("simple-encrypt");
        arguments.add("--key-filter");
        arguments.add(tinyencryptConfig.getKeyId());
        arguments.add("--value-stdin");

        boolean inputNewPassword = false;
        if (BooleanUtils.isTrue(tinyencryptConfig.getEnablePbkdfEncryptionPassword())) {
            arguments.add("--with-pbkdf-encryption");
            String cachedPassword = PBKDF_PASSWORD_CACHE_MAP.getPassword(tinyencryptConfig, vault);
            if (StringUtils.isNotEmpty(cachedPassword)) {
                arguments.add("--password");
                arguments.add(cachedPassword);
            } else {
                inputNewPassword = true;
                arguments.add("--outputs-password");
            }
        }

        final UtilsCommandResult encryptResult = runTinyencrypt(
                tinyencryptConfig,
                input.getBytes(StandardCharsets.UTF_8),
                arguments.toArray(new String[0])
        );
        if (encryptResult.getExitValue() != 0) {
            throw new KeychainAccessException("tinyencrypt encrypt failed: " + encryptResult);
        }
        TinyEncryptResult result = new Gson().fromJson(new String(encryptResult.getStdout(), StandardCharsets.UTF_8), TinyEncryptResult.class);
        if (inputNewPassword && StringUtils.isNotEmpty(result.getPassword())) {
            LOG.info("Store PBKDF password to cache");
            PBKDF_PASSWORD_CACHE_MAP.putPassword(tinyencryptConfig, vault, result.getPassword());
        }

        return result.getResult();
    }

    private static UtilsCommandResult runTinyencrypt(TinyEncryptConfig tinyencryptConfig, byte[] input, String... arguments) throws KeychainAccessException {
        final String tinyencryptCmd = getTinyencryptCommand(tinyencryptConfig);
        final List<String> commands = new ArrayList<>();
        commands.add(tinyencryptCmd);
        if ((arguments == null) || (arguments.length == 0)) {
            throw new KeychainAccessException("tinyencrypt not arguments");
        }
        commands.addAll(Arrays.asList(arguments));
        try {
            final ProcessBuilder processBuilder = new ProcessBuilder(commands);
            final Process process = processBuilder.start();

            // ----- STD IN -----
            final AtomicReference<IOException> inThreadException = new AtomicReference<>();
            final Thread inThread = new Thread(() -> {
                if ((input != null) && (input.length > 0)) {
                    try (OutputStream processIn = process.getOutputStream()) {
                        processIn.write(input);
                    } catch (IOException e) {
                        inThreadException.set(e);
                    }
                }
            });
            inThread.setDaemon(true);
            inThread.setName("tinyencrypt-stdin");

            // ----- STD OUT -----
            final AtomicReference<IOException> outThreadException = new AtomicReference<>();
            final ByteArrayOutputStream outBaos = new ByteArrayOutputStream();
            final Thread outThread = getThread(process.getInputStream(), outBaos, outThreadException, "tinyencrypt-stdout");
            // ----- STD ERR -----
            final AtomicReference<IOException> errThreadException = new AtomicReference<>();
            final ByteArrayOutputStream errBaos = new ByteArrayOutputStream();
            final Thread errThread = getThread(process.getErrorStream(), errBaos, errThreadException, "tinyencrypt-stderr");

            inThread.start();
            outThread.start();
            errThread.start();

            inThread.join();
            if (inThreadException.get() != null) {
                throw inThreadException.get();
            }
            outThread.join();
            if (outThreadException.get() != null) {
                throw outThreadException.get();
            }
            errThread.join();
            if (errThreadException.get() != null) {
                throw errThreadException.get();
            }
            final int exitValue = process.waitFor();

            return new UtilsCommandResult(exitValue, outBaos.toByteArray(), errBaos.toByteArray());
        } catch (Exception e) {
            throw new KeychainAccessException("Run tinyencrypt command failed: " + commands, e);
        }
    }

    private static Thread getThread(InputStream is, ByteArrayOutputStream outBaos, AtomicReference<IOException> outThreadException, String name) {
        final Thread outThread = new Thread(() -> {
            int b;
            try {
                while ((b = is.read()) != -1) {
                    outBaos.write(b);
                }
            } catch (IOException e) {
                outThreadException.set(e);
            }
        });
        outThread.setDaemon(true);
        outThread.setName(name);
        return outThread;
    }

    private static String getTinyencryptCommand(TinyEncryptConfig tinyencryptConfig) {
        if ((tinyencryptConfig != null) && StringUtils.isNoneEmpty(tinyencryptConfig.getTinyencryptCommand())) {
            return tinyencryptConfig.getTinyencryptCommand();
        }
        return DEFAULT_TINY_ENCRYPT_COMMAND;
    }

    private static File getEncryptKeyBasePath(TinyEncryptConfig tinyencryptConfig) {
        final File encryptKeyBase;
        if ((tinyencryptConfig != null) && StringUtils.isNoneEmpty(tinyencryptConfig.getEncryptKeyBasePath())) {
            encryptKeyBase = new File(tinyencryptConfig.getEncryptKeyBasePath());
        } else {
            encryptKeyBase = DEFAULT_ENCRYPTION_KEY_BASE_PATH;
        }
        if (encryptKeyBase.isDirectory()) {
            return encryptKeyBase;
        }
        LOG.info("Make dirs: " + encryptKeyBase);
        encryptKeyBase.mkdirs();
        return encryptKeyBase;
    }

    private static File getTinyencryptConfigFile() throws KeychainAccessException {
        for (File configFile : Arrays.asList(TINYENCRYPT_CONFIG_FILE1, TINYENCRYPT_CONFIG_FILE2)) {
            LOG.info("Check config file: " + configFile + ": " + Arrays.asList(configFile.exists(), configFile.isFile()));
            if (configFile.exists() && configFile.isFile()) {
                return configFile;
            }
        }
        throw new KeychainAccessException("tinyencrypt config file not found.");
    }
}
