package io.tomahawkd.pki.api.server;

import io.tomahawkd.pki.api.server.util.CipherErrorException;
import sun.misc.BASE64Decoder;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SecurityFunctions {

    public static String generateSecretByName(String name) {
        return name;
    }

    public static byte[] generateSymKey(String seed) throws CipherErrorException {
        return generateHash(seed);
    }

    public static KeyPair generateKeyPair() throws CipherErrorException {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }
    }

    public static int generateRandom() {
        byte[] intBytes = generateRandom(Integer.BYTES);
        return ByteBuffer.wrap(intBytes).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
    }

    public static byte[] generateRandom(int bytes) {
        SecureRandom s = new SecureRandom();
        return s.generateSeed(bytes);
    }

    public static byte[] generateHash(String seed) throws CipherErrorException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(seed.getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }
    }

    public static byte[] encryptSymmetric(String keySeed, String random, byte[] data) throws CipherErrorException {
        SecretKey secretKey = new SecretKeySpec(generateSymKey(keySeed), "AES");
        GCMParameterSpec param = new GCMParameterSpec(128, random.getBytes());
        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, param);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherErrorException(e);
        }
    }

    public static byte[] decryptSymmetric(String keySeed, String random, byte[] enc) throws CipherErrorException {
        SecretKey secretKey = new SecretKeySpec(generateSymKey(keySeed), "AES");
        GCMParameterSpec param = new GCMParameterSpec(128, random.getBytes());
        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, param);

            return cipher.doFinal(enc);
        } catch (Exception e) {
            throw new CipherErrorException(e);
        }
    }

    public static byte[] encryptAsymmetric(PublicKey publicKey, byte[] data) throws CipherErrorException {
        try {
            Cipher encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return encCipher.doFinal(data);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CipherErrorException(e);
        }
    }

    public static byte[] encryptAsymmetricAuth(PrivateKey privateKey, byte[] data) throws CipherErrorException {
        try {
            Cipher encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return encCipher.doFinal(data);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CipherErrorException(e);
        }
    }

    public static byte[] decryptAsymmetric(PrivateKey privateKey, byte[] data) throws CipherErrorException {
        try {
            Cipher encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encCipher.init(Cipher.DECRYPT_MODE, privateKey);
            return encCipher.doFinal(data);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CipherErrorException(e);
        }
    }

    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }


}

    /*public static PublicKey readAuthenticateServerPublicKey() throws IOException, CipherErrorException {
        byte[] pubBytes = Base64.getDecoder().decode(
                FileUtil.readFile(FileUtil.rootPath + "/resources/auth.pub"));
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubBytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }
    }

    public static KeyPair readAuthenticateServerKeys() throws IOException, CipherErrorException {
        byte[] priBytes = Base64.getDecoder().decode(
                FileUtil.readFile(FileUtil.rootPath + "/resources/auth.pri"));

        try {
            PublicKey pub = readAuthenticateServerPublicKey();
            PrivateKey pri = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(priBytes));
            return new KeyPair(pub, pri);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }
    }

    public static void generateNewAuthenticateServerKeys() throws CipherErrorException, IOException {
        KeyPair pair = SecurityFunctions.generateKeyPair();
        String pubBase64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        String priBase64 = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        FileUtil.writeFile(FileUtil.rootPath + "/resources/auth.pub", pubBase64, true);
        FileUtil.writeFile(FileUtil.rootPath + "/resources/auth.pri", priBase64, true);
    }
}
*/