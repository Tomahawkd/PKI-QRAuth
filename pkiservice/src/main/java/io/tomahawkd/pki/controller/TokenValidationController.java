package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.util.Utils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/token")
public class TokenValidationController {

	/**
	 * @param data {
	 *             "K": "Base64 encoded Kt public key encrypted Kc,t",
	 *             "id": "Base64 encoded Kt public key encrypted userid,systemid",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Kc,t encrypted Kc public",
	 * "M": "Base64 encoded Ks public key encrypted result message
	 * {
	 * "status": number(0:success, 1:failed),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1",
	 * "KP": "Base64 encoded Kc,t encrypted client key pair",
	 * "EToken": "Base64 encoded Kc public key encrypted token,nonce"}
	 */
	@PostMapping("/init")
	public String tokenInitialization(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> map = Utils.wrapMapFromJson(data);

		return "";
	}

	/**
	 * @param data {
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Ks public key encrypted Kc public",
	 * "M": "Base64 encoded Ks public key encrypted result message
	 * {
	 * "status": number(0:valid, 1:invalid),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1"}
	 */
	@PostMapping("/validate")
	public String tokenValidation(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> map = Utils.wrapMapFromJson(data);

		return "";
	}
}
