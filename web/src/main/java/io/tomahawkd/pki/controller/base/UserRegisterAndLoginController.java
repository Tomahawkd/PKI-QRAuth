package io.tomahawkd.pki.controller.base;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.NotFoundException;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.model.base.UserInfoModel;
import io.tomahawkd.pki.service.SystemLogService;
import io.tomahawkd.pki.service.base.UserInfoService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/user")
public class UserRegisterAndLoginController {
    @Resource
    private UserInfoService userInfoService;
    @Resource
    private SystemLogService systemLogService;


    @PostMapping("/register")
    public boolean userRegister(@RequestBody String user) {

        return true;
    }

    @PostMapping("/Login")
    public boolean userLogin(@RequestBody String user) {

        return true;
    }
}
