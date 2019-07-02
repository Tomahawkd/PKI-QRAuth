package io.tomahawkd.pki.controller;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.exceptions.NotFoundException;
import io.tomahawkd.pki.model.SystemKeyModel;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.model.TokenModel;
import io.tomahawkd.pki.model.UserKeyModel;
import io.tomahawkd.pki.service.*;
import io.tomahawkd.pki.util.ResponseMessage;
import io.tomahawkd.pki.util.SecurityFunctions;
import io.tomahawkd.pki.util.Utils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/token")
public class TokenValidationController {

	@Resource
	private UserKeyService userKeyService;
	@Resource
	private UserTokenService tokenService;
	@Resource
	private UserLogService userLogService;
	@Resource
	private SystemKeyService systemKeyService;
	@Resource
	private SystemLogService systemLogService;

	/**
	 * @param data {
	 *             "K": "Base64 encoded Kt public key encrypted Kc,t",
	 *             "iv": "Base64 encoded Kt public key encrypted iv",
	 *             "id": "Base64 encoded Kt public key encrypted String(userTag;systemid)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "D": "device information(device;ip)"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Kc public",
	 * "M": "result message
	 * {
	 * "status": number(0:success, 1:failed),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1",
	 * "KP": "Base64 encoded Kc,t encrypted client key pair String(base64 public;base64 private)",
	 * "EToken": "Base64 encoded Kc public key encrypted base64String(byteArr(nonce,token))"}
	 */
	@PostMapping("/init")
	public String tokenInitialization(@RequestBody String data)
			throws MalformedJsonException, IOException, CipherErrorException {


		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "K", "iv", "id", "T", "D");

		String[] d = requestMap.get("D").split(";", 2);
		String device = "";
		String ip = "";
		if (d.length == 2) {
			device = d[0];
			ip = d[1];
		}

		byte[] k =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("K")));
		if (k.length != 32) return new Gson().toJson(new ResponseMessage(1, "invalid key"));
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Symmetric key decryption complete.");

		byte[] iv =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("iv")));
		if (iv.length != 16) return new Gson().toJson(new ResponseMessage(1, "invalid iv"));
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "IV decryption complete.");

		String[] id = new String(SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
				Utils.base64Decode(requestMap.get("id")))).split(";");
		String userTag = id[0];
		String systemApi = id[1];
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.INFO,
				"Target: {user: +" + userTag + ", systemApi: " + systemApi + "}");


		SystemKeyModel systemKeyModel = systemKeyService.getByApi(systemApi);
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.INFO,
				"Target: { SystemId: " + systemKeyModel.getSystemId() + "}");

		/* User Key pair */
		UserKeyModel userKeyModel = userKeyService.getKeyPairById(userTag, systemKeyModel.getSystemId());
		if (userKeyModel == null) {
			systemLogService.insertLogRecord(TokenValidationController.class.getName(),
					"tokenInitialization", SystemLogModel.INFO,
					"user: +" + userTag + " not found, initializing");
			userKeyModel = userKeyService.generateKeysFor(userTag, systemKeyModel.getSystemId());
		}

		KeyPair ckp = SecurityFunctions.readKeysFromString(
				userKeyModel.getPrivateKey(),
				userKeyModel.getPublicKey()
		);
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Client key pair load complete.");

		String kpString = userKeyModel.getPublicKey() + ";" + userKeyModel.getPrivateKey();
		String kpResponse = Utils.base64Encode(
				SecurityFunctions.encryptSymmetric(k, iv, kpString.getBytes()));
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Client key pair encryption complete.");


		/* Token */
		TokenModel token = tokenService.generateNewToken(userTag, systemKeyModel.getSystemId(), device, ip);
		byte[] tokenBytes = SecurityFunctions.encryptUsingAuthenticateServerKey(token.serialize());
		int nonce = token.getNonce();
		byte[] tokenArr = ByteBuffer.allocate(tokenBytes.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(tokenBytes).array();
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Client token generate complete.");

		String etokenResponse = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(ckp.getPublic(), tokenArr));
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Client token encryption complete.");

		userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
				device, ip, "Token initialized");

		KeyPair skp = SecurityFunctions.readKeysFromString(
				systemKeyModel.getPrivateKey(),
				systemKeyModel.getPublicKey()
		);
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Server key pair load complete.");

		String kResponse = Utils.base64Encode(ckp.getPublic().getEncoded());

		String tResponse = Utils.responseChallenge(requestMap.get("T"), skp.getPublic());
		String mResponse = new Gson().toJson(new ResponseMessage(0, "Authenticate Complete"));

		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Response data process complete.");

		Map<String, String> responseMap = new HashMap<>();
		responseMap.put("K", kResponse);
		responseMap.put("M", mResponse);
		responseMap.put("T", tResponse);
		responseMap.put("KP", kpResponse);
		responseMap.put("EToken", etokenResponse);

		return new Gson().toJson(responseMap);
	}

	/**
	 * @param data {
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "D": "Device information(device;ip)"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Ks public key encrypted Kc public",
	 * "M": "
	 * {
	 * "status": number(0:valid, 1:invalid),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1"}
	 */
	@PostMapping("/validate")
	public String tokenValidation(@RequestBody String data)
			throws MalformedJsonException, IOException, CipherErrorException, NotFoundException {

		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "EToken", "T", "D");

		String[] d = requestMap.get("D").split(";", 2);
		String device = "";
		String ip = "";
		if (d.length == 2) {
			device = d[0];
			ip = d[1];
		}

		byte[] etoken = SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
				Utils.base64Decode(requestMap.get("EToken")));
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenValidation", SystemLogModel.DEBUG, "EToken decryption complete.");

		int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
		byte[] token = new byte[etoken.length - Integer.BYTES];
		System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);

		byte[] decToken = SecurityFunctions.decryptUsingAuthenticateServerKey(token);
		TokenModel tokenModel = TokenModel.deserialize(decToken);
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenValidation", SystemLogModel.DEBUG, "Token data wrapped complete.");

		ResponseMessage message = new ResponseMessage(1, "Unknown Error");

		int status = 1;
		if (tokenService.validateToken(tokenModel, nonce)) {
			status = 0;
			message.setOK().setMessage("Valid");
			systemLogService.insertLogRecord(TokenValidationController.class.getName(),
					"tokenValidation", SystemLogModel.INFO,
					"Target: {user: +" + tokenModel.getUserId() + "} loaded");
		} else {
			message.setError().setMessage("Invalid");
			systemLogService.insertLogRecord(TokenValidationController.class.getName(),
					"tokenValidation", SystemLogModel.WARN,
					"Token invalid");
		}


		UserKeyModel userKeyModel = userKeyService.getUserById(tokenModel.getUserId());
		if (userKeyModel == null) {
			systemLogService.insertLogRecord(TokenValidationController.class.getName(),
					"tokenValidation", SystemLogModel.FATAL,
					"Token valid but user not exist, this should not happen");
			throw new NotFoundException("User not found");
		}
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenValidation", SystemLogModel.WARN,
				"get user context: " + userKeyModel.toString());

		SystemKeyModel systemKeyModel = systemKeyService.getById(userKeyModel.getSystemId());
		if (systemKeyModel == null) {
			systemLogService.insertLogRecord(TokenValidationController.class.getName(),
					"tokenValidation", SystemLogModel.FATAL,
					"User valid but system not exist, this should not happen");
			throw new NotFoundException("System not found");
		}
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenValidation", SystemLogModel.WARN,
				"get system context: " + systemKeyModel.toString());

		userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
				device, ip, "Token used with status: " + status);

		KeyPair skp = SecurityFunctions.readKeysFromString(
				systemKeyModel.getPrivateKey(),
				systemKeyModel.getPublicKey()
		);
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenValidation", SystemLogModel.DEBUG, "Server key pair load complete.");

		String mResponse = new Gson().toJson(message);
		String tResponse = Utils.responseChallenge(requestMap.get("T"), skp.getPublic());
		String kResponse = userKeyModel.getPublicKey();

		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenValidation", SystemLogModel.DEBUG, "Response data process complete.");

		Map<String, String> responseMap = new HashMap<>();
		responseMap.put("K", kResponse);
		responseMap.put("M", mResponse);
		responseMap.put("T", tResponse);

		return new Gson().toJson(responseMap);
	}
}
