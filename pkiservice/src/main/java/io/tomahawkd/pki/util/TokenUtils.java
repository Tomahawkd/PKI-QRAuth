package io.tomahawkd.pki.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.NotFoundException;
import io.tomahawkd.pki.model.SystemKeyModel;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.model.TokenModel;
import io.tomahawkd.pki.model.UserKeyModel;
import io.tomahawkd.pki.service.*;
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

	/**
	 * @param data {
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "D": "Device information(ip;device)",
	 *             "M": "service message" (optional)
	 *             }
	 * @return {
	 * "K": "Base64 encoded Kc public key",
	 * "M": "
	 * {
	 * "status": number(0:valid, 1:invalid),
	 * "message": "service message"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1",
	 * "U": "Base64 encoded Ks public key encrypted user tag"
	 * }
	 */
	public static <T> String tokenValidate(String data,
	                                       SystemLogService systemLogService,
	                                       UserTokenService tokenService,
	                                       UserLogService userLogService,
	                                       UserKeyService userKeyService,
	                                       SystemKeyService systemKeyService,
	                                       UserIndexService userIndexService,
	                                       Class<T> type,
	                                       ContextCallback<
			                                       TokenRequestMessage<T>,
			                                       UserKeyModel,
			                                       TokenModel,
			                                       SystemKeyModel,
			                                       Message<String>,
			                                       String, String, Message<T>>
			                                       callback) throws IOException {

		TokenRequestMessage<T> requestMessage =
				new Gson().fromJson(data,
						new TypeToken<TokenRequestMessage<T>>() {
						}.getType());

		String[] d = requestMessage.getDevice().split(";", 2);
		String device = "";
		String ip = "";
		if (d.length == 2) {
			ip = d[0];
			device = d[1];
		}

		systemLogService.insertLogRecord(TokenUtils.class.getName(),
				"tokenValidate", SystemLogModel.INFO, "Start handling token.");
		Pair<Integer, byte[]> tokenPair = TokenUtils.decodeToken(requestMessage.getToken());
		int nonce = tokenPair.getKey();
		TokenModel tokenModel = TokenModel.deserialize(tokenPair.getValue());
		systemLogService.insertLogRecord(TokenUtils.class.getName(),
				"tokenValidate", SystemLogModel.DEBUG, "Token data wrapped complete.");

		Message<String> message = new Message<>(1, "Unknown Error");

		if (tokenService.validateToken(tokenModel, nonce)) {
			message.setOK().setMessage("Valid");
			systemLogService.insertLogRecord(TokenUtils.class.getName(),
					"tokenValidate", SystemLogModel.INFO,
					"Target: {user: +" + tokenModel.getUserId() + "} loaded");
		} else {
			message.setError().setMessage("Invalid");
			systemLogService.insertLogRecord(TokenUtils.class.getName(),
					"tokenValidate", SystemLogModel.WARN,
					"Token invalid");
		}

		UserKeyModel userKeyModel = userKeyService.getUserById(tokenModel.getUserId());
		if (userKeyModel == null) {
			systemLogService.insertLogRecord(TokenUtils.class.getName(),
					"tokenValidate", SystemLogModel.FATAL,
					"Token valid but user not exist, this should not happen");
			throw new NotFoundException("User not found");
		}
		systemLogService.insertLogRecord(TokenUtils.class.getName(),
				"tokenValidate", SystemLogModel.INFO,
				"get user context: " + userKeyModel.toString());

		SystemKeyModel systemKeyModel = systemKeyService.getById(userKeyModel.getSystemId());
		if (systemKeyModel == null) {
			systemLogService.insertLogRecord(TokenUtils.class.getName(),
					"tokenValidate", SystemLogModel.FATAL,
					"User valid but system not exist, this should not happen");
			throw new NotFoundException("System not found");
		}
		systemLogService.insertLogRecord(TokenUtils.class.getName(),
				"tokenValidate", SystemLogModel.INFO,
				"get system context: " + systemKeyModel.toString());

		PublicKey spub = SecurityFunctions.readPublicKey(systemKeyModel.getPublicKey());
		systemLogService.insertLogRecord(TokenUtils.class.getName(),
				"tokenValidate", SystemLogModel.DEBUG, "Server public key load complete.");

		String tResponse = Utils.responseChallenge(requestMessage.getTime(), spub);
		ThreadContext.getContext().set(new ThreadLocalData(systemLogService, tResponse));

		userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
				device, ip, "Tokenid " + tokenModel.getCompiledId() +
						" used with status: " + message.getStatus());

		Message<T> responseMessage = null;
		if (message.isOk()) {
			systemLogService.insertLogRecord(TokenUtils.class.getName(),
					"tokenValidate", SystemLogModel.INFO,
					"Context loaded, invoke controller callback");

			responseMessage =
					callback.invoke(requestMessage, userKeyModel, tokenModel, systemKeyModel, message, device, ip);
		}

		String kResponse = userKeyModel.getPublicKey();

		systemLogService.insertLogRecord(TokenUtils.class.getName(),
				"tokenValidate", SystemLogModel.DEBUG, "Response data process complete.");

		String uResponse = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(spub,
				userIndexService.getUserTagById(userKeyModel.getUserId()).getBytes()));

		TokenResponseMessage<T> tokenResponseMessage = new TokenResponseMessage<>();
		tokenResponseMessage.setClientKey(kResponse);
		tokenResponseMessage.setMessage(responseMessage != null ? responseMessage : message);
		tokenResponseMessage.setTime(tResponse);
		tokenResponseMessage.setUserTag(uResponse);

		return new Gson().toJson(tokenResponseMessage);
	}
}
