package io.tomahawkd.simpleserver.controller.base;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.simpleserver.model.SystemLogModel;
import io.tomahawkd.simpleserver.model.base.UserPasswordModel;
import io.tomahawkd.simpleserver.service.SystemLogService;
import io.tomahawkd.simpleserver.service.base.UserPasswordService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserAuthenticationController {

	@Resource
	private UserPasswordService userPasswordService;
	@Resource
	private SystemLogService systemLogService;

	@PostMapping("/register")
	public String registerUser(@RequestBody String body) {

		Map<String, String> bodyData =
				new Gson().fromJson(body, new TypeToken<Map<String, String>>() {}.getType());

		String username = bodyData.get("username");
		String password = bodyData.get("password");

		systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
				"registerUser", SystemLogModel.DEBUG,
				"checkUserExistence: " + username);

		if (userPasswordService.checkUserExistence(username)) {
			systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
					"registerUser", SystemLogModel.WARN, "user existed: " + username);
			return "{\"status\": 1, \"message\": \"user already exist\"}";
		}

		systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
				"registerUser", SystemLogModel.OK, "user is allowed to register");

		systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
				"registerUser", SystemLogModel.INFO, "Registering user: " + username);
		int result = userPasswordService.addUser(new UserPasswordModel(username, password));

		return result == 1 ?
				"{\"status\": 0, \"message\": \"success\"}" :
				"{\"status\": 1, \"message\": \"failed\"}";
	}

	@PostMapping("/login")
	public String userLogin(@RequestBody String user) {

		Map<String, String> bodyData =
				new Gson().fromJson(user, new TypeToken<Map<String, String>>() {}.getType());

		String username = bodyData.get("username");
		String password = bodyData.get("password");

		systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
				SystemLogModel.INFO, "user " + username + " login");

		if (!userPasswordService.checkUserExistence(username)) {      //用户不存在
			systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
					SystemLogModel.WARN, "User " + username + " not exist");
			return "{\"status\": 1, \"message\": \"user not exist\"}";
		}

		if (userPasswordService.checkPassword(username, password)) {      //登陆成功
			systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
					SystemLogModel.OK, "user " + username + " login success");
			return "{\"status\": 0, \"message\": \"success\"}";
		} else {
			//密码错误
			systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
					SystemLogModel.WARN, "User password wrong");
			return "{\"status\": 1, \"message\": \"password incorrect\"}";
		}
	}
}
