package io.tomahawkd.pki.controller;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.model.SystemKeyModel;
import io.tomahawkd.pki.model.SystemLogModel;
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
import java.security.KeyPair;
import java.util.Arrays;
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
	 * "K": "Base64 encoded Kc,t encrypted Kc public",
	 * "M": "result message
	 * {
	 * "status": number(0:success, 1:failed),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1",
	 * "KP": "Base64 encoded Kc,t encrypted client key pair String(base64 public;base64 private)",
	 * "EToken": "Base64 encoded Kc public key encrypted String(token;nonce)"}
	 */
	@PostMapping("/init")
	public String tokenInitialization(@RequestBody String data)
			throws MalformedJsonException, IOException, CipherErrorException {


		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "K", "iv", "id", "T");

		byte[] k =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("K")));
		byte[] iv =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("iv")));

		String[] id = Arrays.toString(SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
				Utils.base64Decode(requestMap.get("id")))).split(";");
		String userTag = id[0];
		String systemApi = id[1];
		systemLogService.insertLogRecord(TokenValidationController.class.getName(),
				"tokenInitialization", SystemLogModel.INFO,
				"Target: {user: +" + userTag + "system: " + systemApi + "}");


		SystemKeyModel systemKeyModel = systemKeyService.getIdByApi(systemApi);

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
		String token = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(ckp.getPublic(),
						tokenService.generateNewToken(userTag, systemKeyModel.getSystemId())));
		int nonce = SecurityFunctions.generateRandom();

		String etokenString = token + ";" + nonce;
		String etokenResponse = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(ckp.getPublic(), etokenString.getBytes()));


		KeyPair skp = SecurityFunctions.readKeysFromString(
				systemKeyModel.getPrivateKey(),
				systemKeyModel.getPublicKey());

		String kResponse = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(skp.getPublic(), ckp.getPublic().getEncoded()));

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
	public String tokenValidation(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "EToken", "T");

		return "";
	}
}
