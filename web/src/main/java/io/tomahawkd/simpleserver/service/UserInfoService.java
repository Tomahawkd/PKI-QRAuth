package io.tomahawkd.simpleserver.service;

import io.tomahawkd.simpleserver.model.UserInfoModel;

public interface UserInfoService {
    UserInfoModel getUserInfo(String username);
    boolean changeUserInfo(UserInfoModel model) throws Exception;
}
