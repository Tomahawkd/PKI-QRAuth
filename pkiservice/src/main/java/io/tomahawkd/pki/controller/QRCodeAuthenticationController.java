package io.tomahawkd.pki.controller;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.model.SystemKeyModel;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.service.QrStatusService;
import io.tomahawkd.pki.service.SystemKeyService;
import io.tomahawkd.pki.service.SystemLogService;
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
		if (k.length != 32) return new Gson().toJson(new ResponseMessage(1, "invalid key"));
		systemLogService.insertLogRecord(QRCodeAuthenticationController.class.getName(),
				"qrNonceGenerate", SystemLogModel.DEBUG, "Symmetric key decryption complete.");

		byte[] iv =
				SecurityFunctions.decryptUsingAuthenticateServerPrivateKey(Utils.base64Decode(requestMap.get("iv")));
		if (iv.length != 16) return new Gson().toJson(new ResponseMessage(1, "invalid iv"));
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

		String mResponse = new Gson().toJson(new ResponseMessage(0, "Generate Complete"));

		Map<String, String> responseMap = new HashMap<>();
		responseMap.put("T", tResponse);
		responseMap.put("nonce2", nonce2Response);
		responseMap.put("M", mResponse);

		return new Gson().toJson(responseMap);
	}

	/**
	 * @param data {
	 *             "M": "message
	 *             {
	 *             "type": "number(1:scanned, 2:confirmed)",
	 *             "nonce2"(appears if type:1):"Base64 encoded Kt public key encrypted nonce2"
	 *             }",
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
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
	public String updateQRStatus(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> requestMap = Utils.wrapMapFromJson(data, "M", "EToken", "T");


		return "";
	}

	/**
	 * @param data {
	 *             "nonce2": "Base64 encoded Kc,t encrypted QrCode nonce",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
	 *             }
	 * @return {
	 * "M": "Base64 encoded Kc,t encrypted result message
	 * {
	 * "type": number(1:scanned, 2:confirmed),
	 * "KP"(appears if type:2): "Base64 encoded Kc,t encrypted client key pair",
	 * "EToken"(appears if type:2): "Base64 encoded Kc public key encrypted token,nonce"
	 * }"
	 * "T": "Base64 encoded Kc,t encrypted challenge number+1"
	 * }
	 */
	@PostMapping("/query")
	public String queryQRStatus(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> map = Utils.wrapMapFromJson(data, "nonce2", "M");

		return "";
	}
}
