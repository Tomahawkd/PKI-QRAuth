package io.tomahawkd.simpleserver.service.base;

import io.tomahawkd.simpleserver.model.base.UserInfoModel;

public interface UserInfoService {
    UserInfoModel getUserInfo(String username);
    boolean changeUserInfo(UserInfoModel model) throws Exception;
}
