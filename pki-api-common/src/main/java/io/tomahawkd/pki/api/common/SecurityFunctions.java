package io.tomahawkd.pki.api.common;

import io.tomahawkd.pki.api.common.exception.CipherErrorException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

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

	public static byte[] encrypt(String keySeed, String random, byte[] data) throws CipherErrorException {
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

	public static byte[] decrypt(String keySeed, String random, byte[] enc) throws CipherErrorException {
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
}
