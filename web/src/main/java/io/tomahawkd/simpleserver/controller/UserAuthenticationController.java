package io.tomahawkd.simpleserver.controller;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.server.ThrowableFunction;
import io.tomahawkd.pki.api.server.Token;
import io.tomahawkd.pki.api.server.util.Message;
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
    public String userRegister(@RequestBody String data, HttpServletRequest request) throws UnsupportedEncodingException, MalformedJsonException, Exception {
        System.out.println(data);
        return Token.getInstance().acceptInitializeAuthenticationMessage(data, request.getRemoteAddr(), request.getHeader("User-Agent")
                , payload -> {
                    try {
                        Map<String, String> bodyData =
                                new Gson().fromJson(payload, new TypeToken<Map<String, String>>() {
                                }.getType());

                        String username = bodyData.get("username");
                        String password = bodyData.get("password");
                        systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                                "registerUser", SystemLogModel.DEBUG,
                                "checkUserExistence: " + username);

                        if (userPasswordService.checkUserExistence(username)) {
                            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                                    "registerUser", SystemLogModel.WARN, "user\"" + username + "\"+ existing");
                            return new Message<String>().setStatus(-1).setMessage( "user already existing");
                        }

                        systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                                "registerUser", SystemLogModel.OK, "user is allowed to register");

                        systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                                "registerUser", SystemLogModel.DEBUG, "Registering user: " + username);
                        int index = userPasswordService.addUser(new UserPasswordModel(username, password));

                        if (index != -1) {
                            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                                    "registerUser", SystemLogModel.OK, "Registering successful: " + username);
                            return new Message<String>().setStatus(index).setMessage( "success");
                        } else {
                            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                                    "registerUser", SystemLogModel.WARN, "Registering failed: " + username);
                            return new Message<String>().setStatus(-1).setMessage( "registering failed");

                        }
                    } catch (JsonSyntaxException e) {

                        throw new MalformedJsonException("Json parse error");
                    }
                }
                , index -> {
                    systemLogService.insertLogRecord(UserAuthenticationController.class.getName(),
                            "deleteUser", SystemLogModel.OK, "Registering failed,delete it");
                    userPasswordService.deleteUser(index);
                }
        );
    }

    @PostMapping(value = "/login")
    public String userLogin(@RequestBody String user, HttpServletRequest request) throws Exception {

        return Token.getInstance().acceptInitializeAuthenticationMessage(user, request.getRemoteAddr(), request.getHeader("User-Agent"),
                payload -> {
                    try {
                        Map<String, String> bodyData =
                                new Gson().fromJson(payload, new TypeToken<Map<String, String>>() {
                                }.getType());
                        String username = bodyData.get("username");
                        String password = bodyData.get("password");
                        systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                                SystemLogModel.DEBUG, "User " + username + " checkUserExistence:" + username);
                        if (!userPasswordService.checkUserExistence(username)) {      //用户不存在
                            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                                    SystemLogModel.WARN, "User " + username + " not exist");
                            return new Message<>(-1, "User not found");
                        }
                        systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                                SystemLogModel.OK, "User " + username + " existing,allowed to login");

                        systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "checkPassword",
                                SystemLogModel.DEBUG, "User " + username + "    password:" + password);
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
                            return new Message<>(index, "success");
                        } else {
                            systemLogService.insertLogRecord(UserAuthenticationController.class.getName(), "userLogin",
                                    SystemLogModel.WARN, "User " + username + " login failed");
                            return new Message<>(-1, "password incorrect");
                        }
                    } catch (JsonSyntaxException e) {
                        throw new MalformedJsonException("Json parse error");
                    }
                }
                , index -> {

                }
        );
    }
    @PostMapping("/logout")
    public void logout(@RequestBody String body,HttpServletRequest request) throws Exception {
        String ip = request.getRemoteAddr();
        String device = request.getHeader("User-Agent");
        String result = Token.getInstance().deinit(body, ip, device);
        Map<String, String> map = new Gson().fromJson(result, new TypeToken<Map<String, String>>() {
        }.getType());
        Map<String, String> M = new Gson().fromJson(map.get("M"), new TypeToken<Map<String, String>>() {
        }.getType());

        request.getSession().invalidate();
    }

    }
