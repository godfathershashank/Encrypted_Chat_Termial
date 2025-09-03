package chat;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Properties;

public class KeyManager {
    private static final SecureRandom RNG = new SecureRandom();
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int PBKDF2_ITERS = 100_000;
    private static final int KEY_BITS = 128; // AES-128

    // Load or create keypair using supplied passphrase (no interactive prompt here)
    public static KeyPair loadOrCreateWithPass(String username, String passphrase) throws Exception {
        File dir = new File("keys");
        if (!dir.exists()) dir.mkdirs();
        File file = new File(dir, username + ".key");

        if (file.exists()) {
            return loadKeyPairFromFile(file, passphrase);
        } else {
            return createAndSaveKeyPair(username, file, passphrase);
        }
    }

    private static KeyPair createAndSaveKeyPair(String username, File file, String pass) throws Exception {
        KeyPair kp = Encryptor.generateRSAKeyPair();
        byte[] privBytes = kp.getPrivate().getEncoded();
        byte[] pubBytes = kp.getPublic().getEncoded();

        byte[] salt = new byte[SALT_LEN]; RNG.nextBytes(salt);
        SecretKey aes = deriveKey(pass, salt);

        byte[] iv = new byte[IV_LEN]; RNG.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aes, new GCMParameterSpec(128, iv));
        byte[] encrypted = cipher.doFinal(privBytes);

        Properties p = new Properties();
        p.setProperty("salt", Base64.getEncoder().encodeToString(salt));
        p.setProperty("iv", Base64.getEncoder().encodeToString(iv));
        p.setProperty("priv", Base64.getEncoder().encodeToString(encrypted));
        p.setProperty("pub", Base64.getEncoder().encodeToString(pubBytes));
        try (FileOutputStream fos = new FileOutputStream(file)) {
            p.store(fos, "Encrypted private key for " + username);
        }
        System.out.println("Keypair created and saved to " + file.getPath());
        return kp;
    }

    private static KeyPair loadKeyPairFromFile(File file, String pass) throws Exception {
        Properties p = new Properties();
        try (FileInputStream fis = new FileInputStream(file)) {
            p.load(fis);
        }
        String saltB64 = p.getProperty("salt");
        String ivB64 = p.getProperty("iv");
        String privB64 = p.getProperty("priv");
        String pubB64 = p.getProperty("pub");
        if (saltB64 == null || ivB64 == null || privB64 == null || pubB64 == null) {
            throw new IOException("Key file missing fields");
        }

        byte[] salt = Base64.getDecoder().decode(saltB64);
        byte[] iv = Base64.getDecoder().decode(ivB64);
        byte[] enc = Base64.getDecoder().decode(privB64);
        byte[] pubBytes = Base64.getDecoder().decode(pubB64);

        SecretKey aes = deriveKey(pass, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aes, new GCMParameterSpec(128, iv));
        byte[] privBytes = cipher.doFinal(enc);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
        return new KeyPair(pub, priv);
    }

    private static SecretKey deriveKey(String passphrase, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, PBKDF2_ITERS, KEY_BITS);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }
}
