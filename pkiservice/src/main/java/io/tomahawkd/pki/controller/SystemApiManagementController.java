package io.tomahawkd.pki.controller;

import io.tomahawkd.pki.service.SystemApiDataService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
@RequestMapping("/manage")
public class SystemApiManagementController {

	@Resource
	private SystemApiDataService apiService;

}
