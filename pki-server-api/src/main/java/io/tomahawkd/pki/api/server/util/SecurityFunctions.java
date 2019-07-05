package io.tomahawkd.pki.api.server.util;

import javafx.util.Pair;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SecurityFunctions {

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

    public static byte[] generateHash(byte[] data) throws CipherErrorException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }
    }

    public static byte[] generateHash(String seed) throws CipherErrorException {
        return generateHash(seed.getBytes());
    }

    public static byte[] encryptSymmetric(byte[] key, byte[] iv, byte[] data) throws CipherErrorException {
        if (key.length != 32) throw new CipherErrorException("Key invalid");
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec param = new IvParameterSpec(iv);
        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, param);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherErrorException(e);
        }
    }

    public static byte[] decryptSymmetric(byte[] key, byte[] iv, byte[] enc) throws CipherErrorException {
        if (key.length != 32) throw new CipherErrorException("Key invalid");
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec param = new IvParameterSpec(iv);
        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
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

    public static PublicKey readAuthenticateServerPublicKey() throws IOException, CipherErrorException {
        byte[] pubBytes = Base64.getDecoder().decode(
                FileUtil.readFile(FileUtil.rootPath + "/resources/auth.pub"));
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubBytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }
    }

    private static PrivateKey readAuthenticateServerPrivateKey() throws IOException, CipherErrorException {
        byte[] priBytes = Utils.base64Decode(
                FileUtil.readFile(FileUtil.rootPath + "/resources/auth.pri"));
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(priBytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }

    }

    public static Pair<byte[], byte[]> readAuthenticateServerKey() throws IOException {
        byte[] data = Utils.base64Decode(
                FileUtil.readFile(FileUtil.rootPath + "/resources/auth.key"));
        byte[] iv = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        byte[] key = new byte[32];
        System.arraycopy(data, 16, key, 0, 32);
        return new Pair<>(iv, key);
    }

    public static byte[] encryptUsingAuthenticateServerPublicKey(byte[] data)
            throws IOException, CipherErrorException {
        PublicKey k = readAuthenticateServerPublicKey();
        return encryptAsymmetric(k, data);
    }

    public static byte[] decryptUsingAuthenticateServerPrivateKey(byte[] data)
            throws IOException, CipherErrorException {
        PrivateKey k = readAuthenticateServerPrivateKey();
        return decryptAsymmetric(k, data);
    }

    public static byte[] encryptUsingAuthenticateServerKey(byte[] data)
            throws IOException, CipherErrorException {
        Pair<byte[], byte[]> keyData = readAuthenticateServerKey();
        return encryptSymmetric(keyData.getValue(), keyData.getKey(), data);
    }

    public static byte[] decryptUsingAuthenticateServerKey(byte[] data)
            throws IOException, CipherErrorException {
        Pair<byte[], byte[]> keyData = readAuthenticateServerKey();
        return decryptSymmetric(keyData.getValue(), keyData.getKey(), data);
    }

    public static KeyPair readAuthenticateServerKeyPair() throws IOException, CipherErrorException {
        return new KeyPair(readAuthenticateServerPublicKey(), readAuthenticateServerPrivateKey());
    }

    public static void generateNewAuthenticateServerKeys() throws CipherErrorException, IOException {
        generateNewAuthenticateServerKeys(FileUtil.rootPath + "resources/");
    }

    public static void generateNewAuthenticateServerKeys(String path) throws CipherErrorException, IOException {
        KeyPair pair = SecurityFunctions.generateKeyPair();
        String pubBase64 = Utils.base64Encode(pair.getPublic().getEncoded());
        String priBase64 = Utils.base64Encode(pair.getPrivate().getEncoded());

        FileUtil.writeFile(path +  "auth.pub", pubBase64, true);
        FileUtil.writeFile(path + "auth.pri", priBase64, true);

        byte[] iv = generateRandom(16);
        byte[] key = generateRandom(32);

        byte[] data = ByteBuffer.allocate(16+32).order(ByteOrder.LITTLE_ENDIAN).put(iv).put(key).array();
        String dataString = Utils.base64Encode(data);
        FileUtil.writeFile(path + "auth.key", dataString, true);
    }

    public static KeyPair readKeysFromString(String pri, String pub) throws CipherErrorException {
        return readKeys(Utils.base64Decode(pri), Utils.base64Decode(pub));

    }

    public static KeyPair readKeys(byte[] pri, byte[] pub) throws CipherErrorException {
        PublicKey publicKey = readPublicKey(pub);
        PrivateKey privateKey = readPrivateKey(pri);
        return new KeyPair(publicKey, privateKey);
    }

    public static PublicKey readPublicKey(String pub) throws CipherErrorException {
        return readPublicKey(Utils.base64Decode(pub));
    }

    public static PrivateKey readPrivateKey(String pri) throws CipherErrorException {
        return readPrivateKey(Utils.base64Decode(pri));
    }

    public static PublicKey readPublicKey(byte[] pub) throws CipherErrorException {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }
    }

    public static PrivateKey readPrivateKey(byte[] pri) throws CipherErrorException {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pri));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CipherErrorException(e);
        }
    }
}

