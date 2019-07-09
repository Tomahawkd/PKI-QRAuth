package io.tomahawkd.pki.api.client.util;

import io.tomahawkd.pki.api.client.exceptions.CipherErrorException;
import javafx.util.Pair;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.PublicKey;

public class TokenUtils {

	public static String encodeToken(byte[] serializedToken, int nonce, PublicKey cpub)
			throws CipherErrorException, IOException {

		byte[] encToken = SecurityFunctions.encryptUsingAuthenticateServerKey(serializedToken);
		byte[] tokenArr = ByteBuffer.allocate(encToken.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(encToken).array();
		return Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(cpub, tokenArr));
	}

	public static Pair<Integer, byte[]> decodeToken(String tokenString)
			throws IOException, CipherErrorException {

		byte[] etoken = SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
				Utils.base64Decode(tokenString));

		int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
		byte[] token = new byte[etoken.length - Integer.BYTES];
		System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);

		byte[] decToken = SecurityFunctions.decryptUsingAuthenticateServerKey(token);

		return new Pair<>(nonce, decToken);
	}
}
