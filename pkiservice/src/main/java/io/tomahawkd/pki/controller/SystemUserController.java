package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.util.Utils;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/manage")
public class SystemUserController {


	@PostMapping("/login")
	public String login(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> map = Utils.wrapMapFromJson(data);

		return "";
	}

	@PostMapping("/register")
	public String register(@RequestBody String data) throws MalformedJsonException {
		Map<String, String> map = Utils.wrapMapFromJson(data);

		return "";
	}

	@GetMapping("/logout")
	public String logout() {
		return "";
	}

	@GetMapping("/info")
	public String info() {
		return "";
	}

	@PostMapping("/keys")
	public String keys(@RequestBody String id) {
		return "";
	}

	@GetMapping("/sysreg")
	public String registerSystem() {
		return "";
	}
}
