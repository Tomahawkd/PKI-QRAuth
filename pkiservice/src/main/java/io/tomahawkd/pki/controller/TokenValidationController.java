package io.tomahawkd.pki.controller;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.exceptions.NotFoundException;
import io.tomahawkd.pki.model.SystemKeyModel;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.model.TokenModel;
import io.tomahawkd.pki.model.UserKeyModel;
import io.tomahawkd.pki.service.SystemKeyService;
import io.tomahawkd.pki.service.SystemLogService;
import io.tomahawkd.pki.service.UserKeyService;
import io.tomahawkd.pki.service.UserTokenService;
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
	private SystemKeyService systemKeyService;
	@Resource
	private SystemLogService systemLogService;

	/**
	 * @param data {
	 *             "K": "Base64 encoded Kt public key encrypted Kc,t",
	 *             "iv": "Base64 encoded Kt public key encrypted iv",
	 *             "id": "Base64 encoded Kt public key encrypted String(userTag;systemid)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
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


		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "K", "iv", "id", "T");

		byte[] k =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("K")));
		if (k.length != 32) return new Gson().toJson(new ResponseMessage(1, "invalid key"));
		byte[] iv =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("iv")));
		if (iv.length != 16) return new Gson().toJson(new ResponseMessage(1, "invalid iv"));

			String[] id = new String(SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
					Utils.base64Decode(requestMap.get("id")))).split(";");
		String userTag = id[0];
		String systemApi = id[1];
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.INFO,
				"Target: {user: +" + userTag + "system: " + systemApi + "}");


		SystemKeyModel systemKeyModel = systemKeyService.getByApi(systemApi);

		/* User Key pair */
		UserKeyModel model = userKeyService.getKeyPairById(userTag, systemKeyModel.getSystemId());
		if (model == null) {
			systemLogService.insertLogRecord(TokenValidationController.class.getName(),
					"tokenInitialization", SystemLogModel.INFO,
					"user: +" + userTag + " not found, initializing");
			model = userKeyService.generateKeysFor(userTag, systemKeyModel.getSystemId());
		}

		KeyPair ckp = SecurityFunctions.readKeysFromString(
				model.getPrivateKey(),
				model.getPublicKey()
		);

		String kpString = model.getPublicKey() + ";" + model.getPrivateKey();
		String kpResponse = Utils.base64Encode(
				SecurityFunctions.encryptSymmetric(k, iv, kpString.getBytes()));


		/* Token */
		TokenModel token = tokenService.generateNewToken(userTag, systemKeyModel.getSystemId());
		byte[] tokenBytes = SecurityFunctions.encryptUsingAuthenticateServerKey(token.serialize());
		int nonce = SecurityFunctions.generateRandom();
		byte[] tokenArr = ByteBuffer.allocate(tokenBytes.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(tokenBytes).array();

		String etokenResponse = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(ckp.getPublic(), tokenArr));


		KeyPair skp = SecurityFunctions.readKeysFromString(
				systemKeyModel.getPrivateKey(),
				systemKeyModel.getPublicKey()
		);

		String kResponse = Utils.base64Encode(ckp.getPublic().getEncoded());

		String tResponse = Utils.responseChallenge(requestMap.get("T"), skp.getPublic());
		String mResponse = new Gson().toJson(new ResponseMessage(0, "Authenticate Complete"));

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
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
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
		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "EToken", "T");

		byte[] etoken = SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
				Utils.base64Decode(requestMap.get("EToken")));

		int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
		byte[] token = new byte[etoken.length - Integer.BYTES];
		System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);

		byte[] decToken = SecurityFunctions.decryptUsingAuthenticateServerKey(token);
		TokenModel tokenModel = TokenModel.deserialize(decToken);

		ResponseMessage message = new ResponseMessage(1, "Unknown Error");

		if (tokenService.validateToken(tokenModel, nonce)) message.setOK().setMessage("Valid");
		else message.setError().setMessage("Invalid");


		UserKeyModel userKeyModel = userKeyService.getUserById(tokenModel.getUserId());
		if (userKeyModel == null) throw new NotFoundException("User not found");
		SystemKeyModel systemKeyModel = systemKeyService.getById(userKeyModel.getSystemId());

		KeyPair skp = SecurityFunctions.readKeysFromString(
				systemKeyModel.getPrivateKey(),
				systemKeyModel.getPublicKey()
		);

		String mResponse = new Gson().toJson(message);
		String tResponse = Utils.responseChallenge(requestMap.get("T"), skp.getPublic());
		String kResponse = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(
						skp.getPublic(), Utils.base64Decode(userKeyModel.getPublicKey())));

		Map<String, String> responseMap = new HashMap<>();
		responseMap.put("K", kResponse);
		responseMap.put("M", mResponse);
		responseMap.put("T", tResponse);

		return new Gson().toJson(responseMap);
	}
}
