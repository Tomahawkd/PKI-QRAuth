package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.util.Utils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/qr")
public class QRCodeAuthenticationController {

	/**
	 * @param data {
	 *             "K": "Base64 encoded Kt public key encrypted Kc,t",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
	 *             }
	 * @return {
	 * "nonce2": "Base64 encoded Kc,t encrypted QrCode nonce",
	 * "T": "Base64 encoded Kc,t encrypted challenge number + 1"
	 * }
	 */
	@PostMapping("/genqr")
	public String qrNonceGenerate(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> map = Utils.wrapMapFromJson(data, "K", "T");

		return "";
	}

	/**
	 * @param data {
	 *             "M": "Base64 encoded Kt public key encrypted message
	 *             {
	 *             "type": number(1:scanned, 2:confirmed),
	 *             "N"(appears if type:1):"Base64 encoded Kc private key signed nonce2"
	 *             }",
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Kc,t encrypted Kc public",
	 * "M": "Base64 encoded Ks public key encrypted result message
	 * {
	 * "status": number(0:valid, 1:invalid),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1"
	 * }
	 */
	@PostMapping("/update")
	public String updateQRStatus(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> map = Utils.wrapMapFromJson(data, "M", "EToken", "T");

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
