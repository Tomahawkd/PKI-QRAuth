package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.NotFoundException;
import io.tomahawkd.pki.service.KeyDistributionService;
import io.tomahawkd.pki.service.SystemLogService;
import io.tomahawkd.pki.util.SecurityFunctions;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;

@RestController
@RequestMapping("/keys")
public class KeyDistributionController {

	@Resource
	private KeyDistributionService service;
	@Resource
	private SystemLogService systemLogService;


	@GetMapping("/auth")
	public String getAuthenticateServerPublicKey(HttpServletRequest request)
			throws IOException, CipherErrorException {
		systemLogService.addAccessLog(KeyDistributionController.class.getName(),
				"getAuthenticateServerPublicKey",
				request.getRemoteAddr(), request.getHeader("User-Agent"));

		return Base64.getEncoder().encodeToString(SecurityFunctions.readAuthenticateServerPublicKey().getEncoded());
	}

	@PostMapping("/server")
	public String getServerPublicKey(HttpServletRequest request, @RequestBody String id) throws NotFoundException {
		String result = service.getPublicKeyById(id);
		if (result == null) throw new NotFoundException("No public key found");
		return result;
	}
}
