package io.tomahawkd.pki.service.util;

import io.tomahawkd.pki.exceptions.CipherErrorException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
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

	public static String securePrivateKey(String userId, String random, String prikey)
			throws CipherErrorException {
		String seed = userId + random;
		return Base64.getEncoder().encodeToString(encrypt(seed, random, Base64.getDecoder().decode(prikey)));
	}

	public static byte[] encrypt(String keySeed, String random, byte[] data) throws CipherErrorException {
		SecretKey secretKey = new SecretKeySpec(generateSymKey(keySeed), "AES");
		GCMParameterSpec param = new GCMParameterSpec(128, random.getBytes());
		try {
			final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, param);

			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException |
				InvalidKeyException | InvalidAlgorithmParameterException |
				IllegalBlockSizeException | BadPaddingException e) {
			throw new CipherErrorException(e);
		}
	}

	public static byte[] decrypt(String keySeed, String random, byte[] enc) throws CipherErrorException {
		SecretKey secretKey = new SecretKeySpec(generateSymKey(keySeed), "AES");
		GCMParameterSpec param = new GCMParameterSpec(128, random.getBytes());
		try {
			final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, param);

			return cipher.doFinal(enc);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException |
				InvalidKeyException | InvalidAlgorithmParameterException |
				IllegalBlockSizeException | BadPaddingException e) {
			throw new CipherErrorException(e);
		}
	}
}
