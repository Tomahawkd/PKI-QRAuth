package io.tomahawkd.simpleserver.controller;

import io.tomahawkd.simpleserver.model.SystemLogModel;
import io.tomahawkd.simpleserver.service.SystemLogService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
public class MainController {
	@Resource
	private SystemLogService service;

	@GetMapping("/")
	public String hello() {
		service.insertLogRecord(MainController.class.getName(),
				"hello", SystemLogModel.INFO, "hello message");
		return "hello";
	}
}
