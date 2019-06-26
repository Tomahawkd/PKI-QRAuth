package io.tomahawkd.simpleserver.controller;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.simpleserver.model.SystemLogModel;
import io.tomahawkd.simpleserver.model.UserPasswordModel;
import io.tomahawkd.simpleserver.service.SystemLogService;
import io.tomahawkd.simpleserver.service.UserPasswordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserAuthenticationController {

	@Resource
	private UserPasswordService userPasswordService;
	@Resource
	private SystemLogService systemLogService;
	@Autowired
	private StringRedisTemplate redisTemplate;

	@PostMapping("/register")
	public String userRegister(HttpServletRequest request, String body) {

		Map<String, String> bodyData =
				new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
				}.getType());

		String username = bodyData.get("username");
		String password = bodyData.get("password");
System.out.println(username);
		systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
				"registerUser", SystemLogModel.DEBUG,
				"checkUserExistence: " + username);

		if (userPasswordService.checkUserExistence(username)) {
			systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
					"registerUser", SystemLogModel.WARN, "user existed: " + username);
			return "{\"status\": -1, \"message\": \"user already existing\"}";
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
/*
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
	}*/

	@PostMapping(value = "/login")
	public String userLogin(@RequestParam("userName") String username, @RequestParam("password") String password,
						 HttpServletRequest request, HttpServletResponse response ) throws Exception {
		response.setContentType("text/html;charset=utf-8");
		response.setCharacterEncoding("utf-8");
		if (!userPasswordService.checkUserExistence(username)) {      //用户不存在
			systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
					SystemLogModel.WARN, "User " + username + " not exist");
			return "{\"status\": -1, \"message\": \"user not exist\"}";
		}
		if (userPasswordService.checkPassword(username, password)) {  //登陆成功
			request.getSession().setAttribute("users", username);//用户名存入该用户的session 中
			return "{\"status\": 0, \"message\": \"success\"}";
		} else
			return "{\"status\": 1, \"message\": \"password incorrect\"}";
	}
}
