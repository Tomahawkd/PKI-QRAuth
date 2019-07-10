package io.tomahawkd.simpleserver.controller;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.server.Token;
import io.tomahawkd.simpleserver.exceptions.MalformedJsonException;

import io.tomahawkd.simpleserver.model.SystemLogModel;
import io.tomahawkd.simpleserver.model.UserInfoModel;
import io.tomahawkd.simpleserver.model.UserPasswordModel;
import io.tomahawkd.simpleserver.service.SystemLogService;
import io.tomahawkd.simpleserver.service.UserInfoService;
import io.tomahawkd.simpleserver.service.UserPasswordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/user/info")
public class UserInfoController {

    @Resource
    private UserInfoService userInfoService;
    @Resource
    private SystemLogService systemLogService;
    @Resource
    private UserPasswordService userPasswordService;

    @Autowired
    private StringRedisTemplate redisTemplate;


    @PostMapping("/data")
    public String getInfoPageById(@RequestBody String body, HttpServletRequest request) throws Exception {
        return Token.getInstance().authentication(body, request.getRemoteAddr(), request.getHeader("User-Agent"),
                (payload, userid) -> {

                    systemLogService.insertLogRecord(UserInfoController.class.getName(),
                            "getInfoPageById", SystemLogModel.DEBUG, "Accept username: " + userid);

                    UserInfoModel model = userInfoService.getUserInfo(Integer.parseInt(userid));

                    if (model == null) {
                        systemLogService.insertLogRecord(UserInfoController.class.getName(), "getInfoPageById",
                                SystemLogModel.WARN, "User not found");
                        return "{\"status\": -1, \"message\": \"user not found\"}";
                    }
                    systemLogService.insertLogRecord(UserInfoController.class.getName(), "getInfoPageById",
                            SystemLogModel.OK, "User found: " + model.toString());
                    return model.toString();
                });
    }


    @PostMapping("/update/info")
    public String updateUserInfo(@RequestBody String body, HttpServletRequest request) throws Exception {

        return Token.getInstance().authentication(body, request.getRemoteAddr(), request.getHeader("User-Agent"),
                (payload, userid) -> {
                    try {
                        Map<String, String> bodyData =
                                new Gson().fromJson(payload, new TypeToken<Map<String, String>>() {
                                }.getType());
                        String name = URLEncoder.encode(bodyData.get("name"), "UTF-8");
                        int sex = Integer.parseInt(bodyData.get("sex"));
                        String email = URLEncoder.encode(bodyData.get("email"), "UTF-8");
                        String phone = URLEncoder.encode(bodyData.get("phone"),"UTF-8");
                        String bio = URLEncoder.encode(bodyData.get("bio"),"UTF-8");

                        Map<String, MultipartFile> imageData =
                                new Gson().fromJson(body, new TypeToken<Map<String, MultipartFile>>() {
                                }.getType());

                        String image_path = this.getImagePath(Integer.parseInt(userid), imageData.get("image"));

                        UserInfoModel model = new UserInfoModel(Integer.parseInt(userid) , name, sex, email, phone, bio, image_path);
                        systemLogService.insertLogRecord(UserInfoController.class.getName(),
                                "changeUserInfo", SystemLogModel.DEBUG, " changingInfo:" + model.toString());
                        boolean result = userInfoService.updateUserInfo(model);

                        if (result) {
                            systemLogService.insertLogRecord(UserInfoController.class.getName(),
                                    "changeUserInfo", SystemLogModel.OK, " change Info successfully");
                            return "{\"status\": 0, \"message\": \"success\"}";


                        } else {
                            systemLogService.insertLogRecord(UserInfoController.class.getName(),
                                    "changeUserInfo", SystemLogModel.WARN, " change Info failed");
                            return "{\"status\": 1, \"message\": \"failed\"}";

                        }
                    } catch (JsonSyntaxException e) {
                        try {
                            throw new MalformedJsonException("Json parse error");
                        } catch (MalformedJsonException ex) {
                            ex.printStackTrace();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return "{\"status\": 1, \"message\": \"failed\"}";
                });
    }

    @PostMapping("/update/password")
    public String updateUserPassword(HttpServletRequest request, @RequestBody String body) throws Exception {
        return Token.getInstance().authentication(body, request.getRemoteAddr(), request.getHeader("User-Agent"),
                (payload, userid) -> {

                    try {
                        Map<String, String> bodyData =
                                new Gson().fromJson(payload, new TypeToken<Map<String, String>>() {
                                }.getType());

                        String password = bodyData.get("password");
                        String new_password = bodyData.get("new_password");

                        UserPasswordModel model = new UserPasswordModel(Integer.parseInt(userid),"",password);
                        systemLogService.insertLogRecord(UserInfoController.class.getName(),
                                "updateUserPassword", SystemLogModel.DEBUG, " updateUserPassword:" + model.toString());

                        boolean result = userPasswordService.updateUserPassword(model, new_password);

                        if (result) {
                            systemLogService.insertLogRecord(UserInfoController.class.getName(),
                                    "updateUserPassword", SystemLogModel.OK, " update user password successfully");
                            return "{\"status\": 0, \"message\": \"success\"}";
                        } else {
                            systemLogService.insertLogRecord(UserInfoController.class.getName(),
                                    "updateUserPassword", SystemLogModel.WARN, " update user password failed");
                            return "{\"status\": 1, \"message\": \"failed\"}";


                        }
                    } catch (Exception e) {
                        try {
                            throw new MalformedJsonException("Json parse error");
                        } catch (MalformedJsonException ex) {
                            ex.printStackTrace();
                        }
                    }
                    return "{\"status\": 1, \"message\": \"failed\"}";
                });

    }


    private String getImagePath(int userid, MultipartFile file) {
        String path = "/user/image";    //图像存储路径
        File dir = new File(path);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        String id = UUID.randomUUID().toString();
        String fileName = file.getOriginalFilename();
        String img = id + fileName.substring(fileName.lastIndexOf("."));

        FileOutputStream imgOut = null;//根据 dir 抽象路径名和 img 路径名字符串创建一个新 File 实例。
        try {
            imgOut = new FileOutputStream(new File(dir, img));

            imgOut.write(file.getBytes());//返回一个字节数组文件的内容
            systemLogService.insertLogRecord(UserInfoController.class.getName(), "getImagePath",
                    SystemLogModel.DEBUG, userid + " image store success..");
            imgOut.close();
            return img;
        } catch (Exception e) {
            e.printStackTrace();
            systemLogService.insertLogRecord(UserInfoController.class.getName(), "getImagePath",
                    SystemLogModel.WARN, userid + " image store failed.");

        }
        return null;
    }


}
