package io.tomahawkd.pki.service.base;

import io.tomahawkd.pki.model.base.UserInfoModel;

public interface UserInfoService {
    UserInfoModel getUserInfo(String username);
    boolean changeUserInfo(UserInfoModel model) throws Exception;
}
