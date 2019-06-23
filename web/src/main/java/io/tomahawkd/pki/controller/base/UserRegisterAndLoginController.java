package io.tomahawkd.pki.controller.base;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.model.base.UserPasswordModel;
import io.tomahawkd.pki.service.SystemLogService;
import io.tomahawkd.pki.service.base.UserPasswordService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserRegisterAndLoginController {
    @Resource
    private UserPasswordService userPasswordService;
    @Resource
    private SystemLogService systemLogService;


    @PostMapping("/register")
    public String userRegister(@RequestBody String body) {

        Map<String, String> bodyData =
                new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
                }.getType());

        systemLogService.insertLogRecord(UserRegisterAndLoginController.class.getName(),
                "checkUserExistence", SystemLogModel.FATAL, "checkUserExistence: " + bodyData.get("username"));
        if (userPasswordService.checkUserExistence(bodyData.get("username"))) {
            systemLogService.insertLogRecord(UserRegisterAndLoginController.class.getName(),
                    "checkUserExistence", SystemLogModel.FATAL, "user existed");
            return "用户已存在";
        }
        systemLogService.insertLogRecord(UserRegisterAndLoginController.class.getName(),
                "checkUserExistence", SystemLogModel.FATAL, "user unexisted");

        systemLogService.insertLogRecord(UserRegisterAndLoginController.class.getName(),
                "userRegister", SystemLogModel.FATAL, "Register username: " + bodyData.get("username"));
        int result = userPasswordService.addUser(new UserPasswordModel(bodyData.get("username"), bodyData.get("password")));

        return result == 1 ? "注册成功" : "注册失败";


    }

    @PostMapping("/Login")
    public String userLogin(@RequestBody String user){
        Map<String, String> bodyData =
                new Gson().fromJson(user, new TypeToken<Map<String, String>>() {}.getType());
        String random = bodyData.get("random");
        String username = bodyData.get("username");
        String password = bodyData.get("password");
        systemLogService.insertLogRecord(UserRegisterAndLoginController.class.getName(), "userLogin",
                SystemLogModel.FATAL, "user " + username + " login");
        if(!userPasswordService.checkUserExistence(username)){      //用户不存在
            systemLogService.insertLogRecord(UserRegisterAndLoginController.class.getName(), "userLogin",
                    SystemLogModel.FATAL, "User " + username + " not exist");
            return "用户不存在";
        }
        boolean success_or_not = userPasswordService.checkPassword(username,password,random);
        if(success_or_not) {      //登陆成功
            systemLogService.insertLogRecord(UserRegisterAndLoginController.class.getName(), "userLogin",
                    SystemLogModel.OK, "user " + username + " login success");
            return "登陆成功";
        }
        else {
            //密码错误
            systemLogService.insertLogRecord(UserRegisterAndLoginController.class.getName(), "userLogin",
                    SystemLogModel.FATAL, "User password wrong");
            return "密码错误";
        }

    }
}
