package io.tomahawkd.pki.controller;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.exceptions.NotFoundException;
import io.tomahawkd.pki.model.SystemKeyModel;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.model.SystemUserModel;
import io.tomahawkd.pki.service.SystemKeyService;
import io.tomahawkd.pki.service.SystemLogService;
import io.tomahawkd.pki.service.SystemUserService;
import io.tomahawkd.pki.util.Utils;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;
import java.util.Map;

/**
 * Version 3.0
 */

@RestController
@RequestMapping("/manage")
public class SystemUserController {

	@Resource
	private SystemUserService service;
	@Resource
	private SystemLogService logService;
	@Resource
	private SystemKeyService systemKeyService;

	@PostMapping("/register")
	public String register(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> map = Utils.wrapMapFromJson(data, "user", "pass");
		service.addSystemUser(map.get("user"), map.get("pass"));
		logService.insertLogRecord(SystemUserController.class.getName(),
				"register", SystemLogModel.INFO, "Add user: " + map.get("user"));
		return "success";
	}

	@PostMapping("/systems")
	public String systems(@RequestBody String data) throws MalformedJsonException, NotFoundException {
		Map<String, String> map = Utils.wrapMapFromJson(data, "user", "pass");
		SystemUserModel user = service.getSystemUserByUsername(map.get("user"), map.get("pass"));
		if (user == null) throw new NotFoundException("User not found");

		List<SystemKeyModel> list = systemKeyService.getByUser(user.getUserId());

		return new Gson().toJson(list);
	}

	@PostMapping("/key")
	public String key(@RequestBody String data) throws MalformedJsonException, NotFoundException {
		Map<String, String> map = Utils.wrapMapFromJson(data, "user", "pass", "system");
		SystemUserModel user = service.getSystemUserByUsername(map.get("user"), map.get("pass"));
		if (user == null) throw new NotFoundException("User not found");

		SystemKeyModel key = systemKeyService.getByApi(map.get("system"));
		if (key == null) return "";
		if (key.getSystemUserId() == user.getUserId()) return key.getPublicKey() + "\n" + key.getPrivateKey();
		return "";
	}

	@PostMapping("/sysreg")
	public String registerSystem(@RequestBody String data)
			throws MalformedJsonException, NotFoundException, CipherErrorException {
		Map<String, String> map = Utils.wrapMapFromJson(data, "user", "pass");
		SystemUserModel user = service.getSystemUserByUsername(map.get("user"), map.get("pass"));
		if (user == null) throw new NotFoundException("User not found");

		systemKeyService.registerSystemApi(user.getUserId());
		return "success";
	}
}
