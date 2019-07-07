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
import io.tomahawkd.pki.util.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
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
	@Resource
	private UserIndexService userIndexService;

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
		if (k.length != 32) return new Gson().toJson(new Message<>(1, "invalid key"));
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Symmetric key decryption complete.");

		byte[] iv =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("iv")));
		if (iv.length != 16) return new Gson().toJson(new Message<>(1, "invalid iv"));
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
		UserKeyModel userKeyModel = userKeyService.getUserByTagAndSystem(userTag, systemKeyModel.getSystemId());
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
		String etokenResponse = TokenUtils.encodeToken(token.serialize(), token.getNonce(), ckp.getPublic());
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Client token encryption complete.");

		userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
				device, ip, "Token initialized");

		PublicKey spub = SecurityFunctions.readPublicKey(systemKeyModel.getPublicKey());
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.DEBUG, "Server public key load complete.");

		String kResponse = Utils.base64Encode(ckp.getPublic().getEncoded());

		String tResponse = Utils.responseChallenge(requestMap.get("T"), spub);
		ThreadContext.getContext().set(tResponse);
		String mResponse = new Gson().toJson(new Message<>(0, "Authenticate Complete"));

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
	 * "message": "service message"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1",
	 * "U": "Base64 encoded Ks public key encrypted user tag"
	 * }
	 */
	@PostMapping("/validate")
	public String tokenValidation(@RequestBody String data)
			throws MalformedJsonException, IOException, CipherErrorException, NotFoundException {

		return TokenUtils.tokenValidate(data,
				systemLogService, tokenService, userLogService,
				userKeyService, systemKeyService, userIndexService, String.class,
				(requestMessage, userKeyModel, tokenModel, systemKeyModel, tokenMessage, device, ip) -> null);
	}
}
