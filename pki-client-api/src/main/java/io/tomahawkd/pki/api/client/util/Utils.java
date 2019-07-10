package io.tomahawkd.pki.api.client.util;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.client.exceptions.*;


import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class Utils {

	public static String base64Encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	public static byte[] base64Decode(String data) {
		try {
			return Base64.getDecoder().decode(data);
		} catch (Exception e) {
			throw new Base64EncodeException("Illegal Base64 Encode");
		}
	}

	public static Map<String, String> wrapMapFromJson(String json, String... params)
			throws ParamNotFoundException, MalformedJsonException {

		try {
			Map<String, String> map = new Gson().fromJson(json, new TypeToken<Map<String, String>>() {
			}.getType());

			for (String param : params) {
				if (!map.containsKey(param)) throw new ParamNotFoundException("Json key not exist: " + json);
			}

			return map;
		} catch (JsonSyntaxException e) {
			throw new MalformedJsonException("Malformed Json: " + json);
		} catch (NullPointerException e) {
			throw new MalformedJsonException("Cannot read json value: " + json);
		}
	}

	public static String responseChallenge(String t, PublicKey key) throws IOException, CipherErrorException {
		return Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(key,
						ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(
										ByteBuffer.wrap(
												SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
														Utils.base64Decode(t)))
												.order(ByteOrder.LITTLE_ENDIAN).getInt() + 1).array()));
	}



	public static String generateEtoken(byte[] token,int nonce,PublicKey key) throws CipherErrorException {
		byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonce+1).put(token).array();
		return Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(key, tokenArr));
	}
}
