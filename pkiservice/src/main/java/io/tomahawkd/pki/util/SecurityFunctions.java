package io.tomahawkd.pki.util;

import io.tomahawkd.pki.exceptions.CipherErrorException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
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

	public static byte[] generateRandom() {
		SecureRandom s = new SecureRandom();
		return s.generateSeed(12);
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
