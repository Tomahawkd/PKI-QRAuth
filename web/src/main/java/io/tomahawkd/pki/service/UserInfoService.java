package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.UserInfoModel;

import java.util.List;

public interface UserInfoService {
    UserInfoModel getUserInfo(String username);
    boolean changeUserInfo(UserInfoModel model) throws Exception;
}
