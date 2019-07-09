package io.tomahawkd.pki.controller;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.exceptions.NotFoundException;
import io.tomahawkd.pki.model.*;
import io.tomahawkd.pki.service.*;
import io.tomahawkd.pki.util.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/qr")
public class QRCodeAuthenticationController {

	@Resource
	private QrStatusService qrStatusService;
	@Resource
	private SystemKeyService systemKeyService;
	@Resource
	private SystemLogService systemLogService;
	@Resource
	private UserTokenService tokenService;
	@Resource
	private UserLogService userLogService;
	@Resource
	private UserKeyService userKeyService;
	@Resource
	private UserIndexService userIndexService;

	/**
	 * @param data {
	 *             "K": "Base64 encoded Kt public key encrypted Kc,t",
	 *             "iv": "Base64 encoded Kt public key encrypted iv"
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "system": "systemid"
	 *             }
	 * @return {
	 * "nonce2": "Base64 encoded Kc,t encrypted QrCode nonce",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1",
	 * "M": "result message
	 * {
	 * "status": number(0:success, 1:failed),
	 * "message": "status description"
	 * }",
	 * }
	 */
	@PostMapping("/genqr")
	public String qrNonceGenerate(@RequestBody String data)
			throws MalformedJsonException, CipherErrorException, IOException {

		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "K", "iv", "T", "system");

		byte[] k =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("K")));
		if (k.length != 32) return new Gson().toJson(new Message<>(1, "invalid key"));
		systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
				"qrNonceGenerate", SystemLogModel.DEBUG, "Symmetric key decryption complete.");

		byte[] iv =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("iv")));
		if (iv.length != 16) return new Gson().toJson(new Message<>(1, "invalid iv"));
		systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
				"qrNonceGenerate", SystemLogModel.DEBUG, "IV decryption complete.");

		int nonce = qrStatusService.generateQrNonce(Utils.base64Encode(k), Utils.base64Encode(iv)).getNonce();
		byte[] nonceBytes = ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).array();
		systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
				"qrNonceGenerate", SystemLogModel.DEBUG, "QR code nonce generate complete.");

		SystemKeyModel systemKeyModel = systemKeyService.getByApi(requestMap.get("system"));
		PublicKey spub = SecurityFunctions.readPublicKey(systemKeyModel.getPublicKey());

		systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
				"qrNonceGenerate", SystemLogModel.DEBUG, "Server public key load complete.");

		String nonce2Response = Utils.base64Encode(SecurityFunctions.encryptSymmetric(k, iv, nonceBytes));
		String tResponse = Utils.responseChallenge(requestMap.get("T"), spub);
		ThreadContext.getContext().set(tResponse);

		String mResponse = new Gson().toJson(new Message<>(0, "Generate Complete"));

		Map<String, String> responseMap = new HashMap<>();
		responseMap.put("T", tResponse);
		responseMap.put("nonce2", nonce2Response);
		responseMap.put("M", mResponse);

		return new Gson().toJson(responseMap);
	}

	/**
	 * @param data { "M": {
	 *             "status": "number(1:scanned, 2:confirmed)",
	 *             "message":"Base64 encoded Kt public key encrypted nonce2(1), 1:true/0:false(2)"
	 *             }
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "D": "ip;device"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Kc,t encrypted Kc public",
	 * "M": "result message
	 * {
	 * "status": number(0:valid, 1:invalid),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1"
	 * }
	 */
	@PostMapping("/update")
	public String updateQRStatus(@RequestBody String data)
			throws MalformedJsonException, IOException, CipherErrorException {

		return TokenUtils.tokenValidate(data,
				systemLogService, tokenService,
				userLogService, userKeyService,
				systemKeyService, userIndexService, String.class,
				(requestMessage, userKeyModel, tokenModel, systemKeyModel, tokenMessage, device, ip) -> {

					int status = requestMessage.getMessage().getStatus();
					systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
							"updateQRStatus", SystemLogModel.DEBUG,
							"Get status: " + status);

					// scanned
					if (status == 1) {

						systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
								"updateQRStatus", SystemLogModel.INFO,
								"Client ask to update status to scanned.");

						String nonceString = requestMessage.getMessage().getMessage();
						int nonce = ByteBuffer.wrap(
								SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
										Utils.base64Decode(nonceString))).order(ByteOrder.LITTLE_ENDIAN).getInt();

						qrStatusService.updateQrNonceStatusToScanned(tokenModel.getTokenId(), nonce);
						systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
								"updateQRStatus", SystemLogModel.INFO,
								"update status to scanned.");
						userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
								device, ip, "Client scanned the Qr code");

						return new Message<>(0, "Status update to Scanned");

						// confirmed
					} else if (status == 2) {

						systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
								"updateQRStatus", SystemLogModel.INFO,
								"Client ask to update status to confirmed.");

						String stateString = new String(
								SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(
										Utils.base64Decode(requestMessage.getMessage().getMessage())));
						if (stateString.equals("1")) {
							qrStatusService.updateQrNonceStatusToConfirmed(tokenModel.getTokenId());

							systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
									"updateQRStatus", SystemLogModel.INFO,
									"update status to confirmed.");
							userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
									device, ip, "Client confirm to login using the Qr code");
							return new Message<>(0, "Status update to Confirm");

						} else {
							qrStatusService.clearStatus(tokenModel.getTokenId());
							systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
									"updateQRStatus", SystemLogModel.INFO,
									"Client canceled confirm");
							userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
									device, ip, "Client canceled to login using the Qr code");
							return new Message<>(0, "Status reset");
						}

					} else {
						systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
								"updateQRStatus", SystemLogModel.WARN,
								"Client send malformed status");
						return new Message<>(1, "Invalid status");
					}
				});
	}

	/**
	 * @param data {
	 *             "nonce2": "Base64 encoded QrCode nonce",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "system": "systemid",
	 *             "D": "ip;device"
	 *             }
	 * @return {
	 * "M": "result message
	 * {
	 * "type": "number(-1:not exist, 0:not scanned, 1:scanned, 2:confirmed)",
	 * "message": "message"
	 * }"
	 * "T": "Base64 encoded Kc,t encrypted challenge number+1"
	 * "KP"(appears if type:2): "Base64 encoded Kc,t encrypted client key pair",
	 * "EToken"(appears if type:2): "Base64 encoded Kc public key encrypted token,nonce"
	 * }
	 */
	@PostMapping("/query")
	public String queryQRStatus(@RequestBody String data) throws MalformedJsonException, IOException {

		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "nonce2", "T", "D", "system");

		String[] d = requestMap.get("D").split(";", 2);
		String device = "";
		String ip = "";
		if (d.length == 2) {
			ip = d[0];
			device = d[1];
		}

		int nonce = ByteBuffer.wrap(
						Utils.base64Decode(requestMap.get("nonce2"))).order(ByteOrder.LITTLE_ENDIAN).getInt();

		SystemKeyModel systemKeyModel = systemKeyService.getByApi(requestMap.get("system"));
		PublicKey spub = SecurityFunctions.readPublicKey(systemKeyModel.getPublicKey());

		systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
				"queryQRStatus", SystemLogModel.DEBUG, "Server public key load complete.");

		String tResponse = Utils.responseChallenge(requestMap.get("T"), spub);
		ThreadContext.getContext().set(tResponse);

		Map<String, String> message = new HashMap<>();
		QrStatusModel model = qrStatusService.getQrStatusByNonce(nonce);
		if (model == null) {
			message.put("type", "-1");
			message.put("message", "qrcode invalid");

			Map<String, String> responseMap = new HashMap<>();
			responseMap.put("M", new Gson().toJson(message));
			responseMap.put("T", tResponse);

			systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
					"queryQRStatus", SystemLogModel.DEBUG, "Invalid query nonce to qrcode.");

			return new Gson().toJson(responseMap);
		} else if (model.getStatus() != 1 && model.getStatus() != 2) {
			message.put("type", "0");
			message.put("message", "qrcode not scanned");

			Map<String, String> responseMap = new HashMap<>();
			responseMap.put("M", new Gson().toJson(message));
			responseMap.put("T", tResponse);

			return new Gson().toJson(responseMap);
		} else if (model.getStatus() == 1) {
			message.put("type", "1");
			message.put("message", "qrcode scanned");

			Map<String, String> responseMap = new HashMap<>();
			responseMap.put("M", new Gson().toJson(message));
			responseMap.put("T", tResponse);

			systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
					"queryQRStatus", SystemLogModel.DEBUG, "query nonce to qrcode status scanned.");

			return new Gson().toJson(responseMap);

		} else {

			systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
					"queryQRStatus", SystemLogModel.DEBUG, "query nonce to qrcode status confirmed.");

			byte[] k = Utils.base64Decode(model.getSymKey());
			byte[] iv = Utils.base64Decode(model.getIv());

			TokenModel token = tokenService.getTokenById(model.getTokenId());
			int userId = token.getUserId();

			/* User Key pair */
			UserKeyModel userKeyModel = userKeyService.getUserById(userId);
			if (userKeyModel == null) {
				systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
						"queryQRStatus", SystemLogModel.FATAL,
						"user: +" + userId + " not found");
				throw new NotFoundException("User not found");
			}

			KeyPair ckp = SecurityFunctions.readKeysFromString(
					userKeyModel.getPrivateKey(),
					userKeyModel.getPublicKey()
			);
			systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
					"queryQRStatus", SystemLogModel.DEBUG, "Client key pair load complete.");

			String kpString = userKeyModel.getPublicKey() + ";" + userKeyModel.getPrivateKey();
			String kpResponse = Utils.base64Encode(
					SecurityFunctions.encryptSymmetric(k, iv, kpString.getBytes()));
			systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
					"queryQRStatus", SystemLogModel.DEBUG, "Client key pair encryption complete.");


			/* Token */
			TokenModel newToken = tokenService.generateNewTokenViaQrCode(userId, device, ip);
			String etokenResponse = TokenUtils.encodeToken(newToken.serialize(), newToken.getNonce(), ckp.getPublic());
			systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
					"queryQRStatus", SystemLogModel.DEBUG, "Client token encryption complete.");

			userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
					device, ip, "Token initialized via qr code");

			message.put("type", "2");
			message.put("message", "qrcode confirmed");

			Map<String, String> responseMap = new HashMap<>();
			responseMap.put("M", new Gson().toJson(message));
			responseMap.put("T", tResponse);
			responseMap.put("KP", kpResponse);
			responseMap.put("EToken", etokenResponse);

			return new Gson().toJson(responseMap);
		}
	}
}
