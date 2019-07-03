package io.tomahawkd.pki.api.client.util;

import io.tomahawkd.pki.api.client.exceptions.CipherErrorException;
import io.tomahawkd.pki.api.client.exceptions.*;
import io.tomahawkd.pki.api.client.util.SecurityFunctions;
import io.tomahawkd.pki.api.client.util.Utils;
import io.tomahawkd.pki.api.client.*;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
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
		return ByteBuffer.wrap(intBytes).order(ByteOrder.LITTLE_ENDIAN).getInt(Integer.BYTES);
	}

	public static byte[] generateRandom(int bytes) {
		SecureRandom s = new SecureRandom();
		return s.generateSeed(bytes);
	}

	public static byte[] generateHash(byte[] seed) throws CipherErrorException {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(seed);
		} catch (NoSuchAlgorithmException e) {
			throw new CipherErrorException(e);
		}
	}

	public static byte[] generateHash(String seed) throws CipherErrorException {
		return generateHash(seed.getBytes());
	}

	public static byte[] encryptSymmetric(byte[] key, byte[] iv, byte[] data) throws CipherErrorException {
		if (key.length !=32) throw new CipherErrorException("Key invalid");
		SecretKey secretKey = new SecretKeySpec(key, "AES");
		GCMParameterSpec param = new GCMParameterSpec(128, iv);
		try {
			final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, param);

			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new CipherErrorException(e);
		}
	}

	public static byte[] decryptSymmetric(byte[] key, byte[] iv, byte[] enc) throws CipherErrorException {
		if (key.length !=32) throw new CipherErrorException("Key invalid");
		SecretKey secretKey = new SecretKeySpec(key, "AES");
		GCMParameterSpec param = new GCMParameterSpec(128, iv);
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
		byte[] priBytes = Base64.getDecoder().decode(
				FileUtil.readFile(FileUtil.rootPath + "/resources/auth.pri"));
		try {
			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(priBytes));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new CipherErrorException(e);
		}

	}

	public static byte[] decryptUsingAuthenticateServerPrivateKey(byte[] data)
			throws IOException, CipherErrorException {
		PrivateKey k = readAuthenticateServerPrivateKey();
		return decryptAsymmetric(k, data);
	}

	public static KeyPair readAuthenticateServerKeys() throws IOException, CipherErrorException {
		return new KeyPair(readAuthenticateServerPublicKey(), readAuthenticateServerPrivateKey());
	}

	public static void generateNewAuthenticateServerKeys() throws CipherErrorException, IOException {
		KeyPair pair = SecurityFunctions.generateKeyPair();
		String pubBase64 = Utils.base64Encode(pair.getPublic().getEncoded());
		String priBase64 = Utils.base64Encode(pair.getPrivate().getEncoded());

		FileUtil.writeFile(FileUtil.rootPath + "/resources/auth.pub", pubBase64, true);
		FileUtil.writeFile(FileUtil.rootPath + "/resources/auth.pri", priBase64, true);
	}

	public static KeyPair readKeysFromString(String pri, String pub) throws CipherErrorException {
		try {
			PublicKey publicKey =
					KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Utils.base64Decode(pub)));
			PrivateKey privateKey =
					KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Utils.base64Decode(pri)));
			return new KeyPair(publicKey, privateKey);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new CipherErrorException(e);
		}

	}
}
