package io.tomahawkd.simpleserver.controller;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.simpleserver.exceptions.MalformedJsonException;
import io.tomahawkd.simpleserver.model.SystemLogModel;
import io.tomahawkd.simpleserver.model.UserPasswordModel;
import io.tomahawkd.simpleserver.service.SystemLogService;
import io.tomahawkd.simpleserver.service.UserPasswordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
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
    public String userRegister(@RequestBody String body) throws UnsupportedEncodingException, MalformedJsonException {

        try {
            Map<String, String> bodyData =
                    new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
                    }.getType());

            String username = bodyData.get("username");
            String password = bodyData.get("password");
            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                    "registerUser", SystemLogModel.DEBUG,
                    "checkUserExistence: " + username);

            if (userPasswordService.checkUserExistence(username)) {
                systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                        "registerUser", SystemLogModel.WARN, "user\"" + username + "\"+ existing");
                return "{\"status\": -1, \"message\": \"user already existing\"}";
            }

            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                    "registerUser", SystemLogModel.OK, "user is allowed to register");

            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                    "registerUser", SystemLogModel.DEBUG, "Registering user: " + username);
            int result = userPasswordService.addUser(new UserPasswordModel(username, password));

            if (result != -1) {
                systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                        "registerUser", SystemLogModel.OK, "Registering successful: " + username);
                return "{\"status\": 0, \"message\": \"success\"}";
            } else {
                systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                        "registerUser", SystemLogModel.WARN, "Registering failed: " + username);
                return "{\"status\": 1, \"message\": \"failed\"}";

            }
        } catch (JsonSyntaxException e) {

            throw new MalformedJsonException("Json parse error");
        }

    }

    @PostMapping(value = "/login")
    public String userLogin(@RequestBody String user, HttpServletRequest request, HttpServletResponse response) throws Exception {

        try {
            Map<String, String> bodyData =
                    new Gson().fromJson(user, new TypeToken<Map<String, String>>() {
                    }.getType());

            String username = bodyData.get("username");
            String password = bodyData.get("password");
            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                    SystemLogModel.DEBUG, "User " + username + " checkUserExistence:" + username);
            if (!userPasswordService.checkUserExistence(username)) {      //用户不存在
                systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                        SystemLogModel.WARN, "User " + username + " not exist");
                return "{\"status\": -1, \"message\": \"user not exist\"}";
            }
            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                    SystemLogModel.OK, "User " + username + " existing,allowed to login");

            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "checkPassword",
                    SystemLogModel.DEBUG, "User " + username + "    password:"+password);
            int index = userPasswordService.checkPassword(username, password);
            if (index != -1) {  //登陆成功
                systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                        SystemLogModel.OK, "User " + username + " login successfully");
                HttpSession session = request.getSession();
                session.setAttribute("userid", index);//用户名存入该用户的session 中
                session.setAttribute("username", username);//用户名存入该用户的session 中
                redisTemplate.opsForValue().set("loginUser:" + index, session.getId());
                //Cookie cookie = new Cookie("SESSIONID",session.getId());
                //cookie.setPath(request.getContextPath());
                //response.addCookie(cookie);
                return "{\"status\": 0, \"message\": \"success\"}";
            } else {
                systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                        SystemLogModel.WARN, "User " + username + " login failed");
                return "{\"status\": 1, \"message\": \"password incorrect\"}";

            }
        } catch (JsonSyntaxException e) {
            throw  new MalformedJsonException("Json parse error");
        }
    }

}
