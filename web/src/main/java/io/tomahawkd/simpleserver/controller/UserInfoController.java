package io.tomahawkd.simpleserver.controller;

import io.tomahawkd.simpleserver.exceptions.NotFoundException;
import io.tomahawkd.simpleserver.model.SystemLogModel;
import io.tomahawkd.simpleserver.model.UserInfoModel;
import io.tomahawkd.simpleserver.service.SystemLogService;
import io.tomahawkd.simpleserver.service.UserInfoService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
@RequestMapping("/user/info")
public class UserInfoController {

	@Resource
	private UserInfoService userInfoService;
	@Resource
	private SystemLogService systemLogService;

	// http://127.0.0.1/user/info/liucheng
	@GetMapping("/data/{user}")
	public String getInfoPageById(@PathVariable String user) throws NotFoundException {
		systemLogService.insertLogRecord(UserInfoController.class.getName(),
				"getInfoPageById", SystemLogModel.INFO, "Accept username: " + user);
		UserInfoModel model = userInfoService.getUserInfo(user);
		if (model == null) {
			systemLogService.insertLogRecord(UserInfoController.class.getName(), "getInfoPageById",
							SystemLogModel.FATAL, "User not found");
			throw new NotFoundException("User not found");
		}
		systemLogService.insertLogRecord(UserInfoController.class.getName(), "getInfoPageById",
				SystemLogModel.DEBUG, "User found: " + model.toString());
		return model.toString();
	}
}
