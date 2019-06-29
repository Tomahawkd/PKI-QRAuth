package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.service.SystemLogService;
import io.tomahawkd.pki.service.UserKeyService;
import io.tomahawkd.pki.util.SecurityFunctions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;

@RestController
@RequestMapping("/keys")
public class KeyDistributionController {

	@Resource
	private UserKeyService userKeyService;
	@Resource
	private SystemLogService systemLogService;


	@GetMapping("/auth/pubkey")
	public String getAuthenticateServerPublicKey(HttpServletRequest request)
			throws IOException, CipherErrorException {
		systemLogService.addAccessLog(KeyDistributionController.class.getName(),
				"getAuthenticateServerPublicKey",
				request.getRemoteAddr(), request.getHeader("User-Agent"));

		return Base64.getEncoder().encodeToString(SecurityFunctions.readAuthenticateServerPublicKey().getEncoded());
	}

}
