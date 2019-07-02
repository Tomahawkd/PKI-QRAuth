package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.service.UserLogService;
import io.tomahawkd.pki.util.Utils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.Map;

/**
 * Version 2.0 Implementation
 */

@RestController
@RequestMapping("/user")
public class UserManagementController {

	@Resource
	private UserLogService userLogService;

	/**
	 * @param data {
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Kc public key encrypted Kc,t",
	 * "M": "Base64 encoded Kc,t encrypted [user log]",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1"
	 * }
	 */
	@PostMapping("/log")
	public String getUserLogById(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> bodyData = Utils.wrapMapFromJson(data, "EToken", "T");

		return "";
	}

	/**
	 * @param data {
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Kc public key encrypted Kc,t",
	 * "M": "Base64 encoded Kc,t encrypted [sha256 hashed user token]",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1"
	 * }
	 */
	@PostMapping("/token/list")
	public String listToken(String data) throws MalformedJsonException {
		Map<String, String> bodyData = Utils.wrapMapFromJson(data, "EToken", "T");

		return "";
	}

	/**
	 * @param data {
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "M": "Base64 encoded Kt public key encrypted token hash to revoke",
	 *             "D": "Device information(device;ip)"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Ks public key encrypted Kc public",
	 * "M": "Base64 encoded Ks public key encrypted result message
	 * {
	 * "status": number(0:valid, 1:invalid),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1"
	 * }
	 */
	@PostMapping("/token/revoke")
	public String revokeToken(String data) throws MalformedJsonException {
		Map<String, String> bodyData = Utils.wrapMapFromJson(data, "EToken", "T");

		return "";
	}

	/**
	 * @param data {
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "D": "Device information(device;ip)"
	 *             }
	 * @return {
	 * "K": "Base64 encoded Ks public key encrypted Kc public",
	 * "M": "Base64 encoded Ks public key encrypted result message
	 * {
	 * "status": number(0:valid, 1:invalid),
	 * "message": "status description"
	 * }",
	 * "T": "Base64 encoded Ks public key encrypted challenge number + 1"
	 * }
	 */
	@PostMapping("/keys/regen")
	public String regenerateKeys(String data) throws MalformedJsonException {
		Map<String, String> bodyData = Utils.wrapMapFromJson(data, "EToken", "T", "D");

		return "";
	}
}
