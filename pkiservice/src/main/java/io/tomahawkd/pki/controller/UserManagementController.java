package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.model.UserLogModel;
import io.tomahawkd.pki.service.*;
import io.tomahawkd.pki.util.Message;
import io.tomahawkd.pki.util.SecurityFunctions;
import io.tomahawkd.pki.util.TokenUtils;
import io.tomahawkd.pki.util.Utils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Map;

/**
 * Version 2.0 Implementation
 */

@RestController
@RequestMapping("/user")
public class UserManagementController {

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
	@PostMapping("/log")
	public String getUserLogById(@RequestBody String data) throws MalformedJsonException, IOException {
		return TokenUtils.tokenValidate(data,
				systemLogService, tokenService, userLogService,
				userKeyService, systemKeyService, userIndexService, List.class,
				(requestMessage, userKeyModel, tokenModel, systemKeyModel, tokenMessage, device, ip) -> {
					List<UserLogModel> logModelList =
							userLogService.getUserActivitiesById(userKeyModel.getUserId(), userKeyModel.getSystemId());
					Message<List> message = new Message<>();
					return message.setOK().setMessage(logModelList);
				});
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
	@PostMapping("/token/list")
	public String listToken(@RequestBody String data) throws MalformedJsonException, IOException {
		return TokenUtils.tokenValidate(data,
				systemLogService, tokenService, userLogService,
				userKeyService, systemKeyService, userIndexService, List.class,
				(requestMessage, userKeyModel, tokenModel, systemKeyModel, tokenMessage, device, ip) -> {

					List<Map<String, String>> tokenIdList =
							tokenService.getTokenListByUserId(userKeyModel.getUserId());

					return new Message<List>().setOK().setMessage(tokenIdList);
				});
	}

	/**
	 * @param data {
	 *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
	 *             "T": "Base64 encoded Kt public key encrypted challenge number",
	 *             "D": "Device information(device;ip)"
	 *             "M": {
	 *             "status": 0
	 *             "message": "single token id to revoke"
	 *             }
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
	@PostMapping("/token/revoke")
	public String revokeToken(@RequestBody String data) throws MalformedJsonException, IOException {
		return TokenUtils.tokenValidate(data,
				systemLogService, tokenService, userLogService,
				userKeyService, systemKeyService, userIndexService, String.class,
				(requestMessage, userKeyModel, tokenModel, systemKeyModel, tokenMessage, device, ip) -> {

					String token = requestMessage.getMessage().getMessage();
					int tokenId = ByteBuffer.wrap(
							SecurityFunctions.decryptUsingAuthenticateServerKey(
									Utils.base64Decode(token))).order(ByteOrder.LITTLE_ENDIAN).getInt();

					int res = tokenService.deleteUserTokenById(tokenId, tokenModel.getUserId());
					if (res != 1) {

						systemLogService.insertLogRecord(UserManagementController.class.getName(),
								"revokeToken", SystemLogModel.WARN,
								"User " + tokenModel.getUserId() +
										" try to delete token " + tokenId + " with failure");
						return new Message<String>().setError().setMessage("You are not the token owner");
					} else {
						systemLogService.insertLogRecord(UserManagementController.class.getName(),
								"revokeToken", SystemLogModel.INFO,
								"User " + tokenModel.getUserId() +
										" try to delete token " + tokenId + " with success");
						userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
								device, ip, "Token revoked");
						return new Message<String>().setOK().setMessage("Revoke Complete");
					}
				});
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
	@PostMapping("/keys/regen")
	public String regenerateKeys(@RequestBody String data) throws MalformedJsonException, IOException {
		return TokenUtils.tokenValidate(data,
				systemLogService, tokenService, userLogService,
				userKeyService, systemKeyService, userIndexService, String.class,
				(requestMessage, userKeyModel, tokenModel, systemKeyModel, tokenMessage, device, ip) -> {

					userKeyService.regenerateKeysAndDeleteTokenFor(userKeyModel.getUserId());
					systemLogService.insertLogRecord(UserManagementController.class.getName(),
							"regenerateKeys", SystemLogModel.INFO,
							"User " + tokenModel.getUserId() + " reset key pair");
					userLogService.insertUserActivity(userKeyModel.getUserId(), userKeyModel.getSystemId(),
							device, ip, "Key pair reset");
					return new Message<String>().setOK().setMessage("Key pair regenerated");
				});
	}
}
