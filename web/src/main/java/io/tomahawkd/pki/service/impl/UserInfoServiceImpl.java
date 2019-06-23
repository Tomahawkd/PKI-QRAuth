package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserInfoDao;
import io.tomahawkd.pki.model.UserInfoModel;
import io.tomahawkd.pki.service.UserInfoService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.List;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserInfoServiceImpl implements UserInfoService {
    @Resource
    private UserInfoDao dao;
    @Override
    public UserInfoModel getUserInfo(String username) {
        return dao.getUserInfo(username);
    }

    @Override
    public boolean changeUserInfo(UserInfoModel model)  {
        int result =  dao.updateUserInfo(model);
        return result == 1;
    }
}
