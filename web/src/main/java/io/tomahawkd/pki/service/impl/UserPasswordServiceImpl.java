package io.tomahawkd.pki.service.impl;


import io.tomahawkd.pki.dao.UserPasswordDao;
import io.tomahawkd.pki.model.UserInfoModel;
import io.tomahawkd.pki.model.UserPasswordModel;
import io.tomahawkd.pki.service.UserPasswordService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.List;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserPasswordServiceImpl implements UserPasswordService {
    @Resource
    private UserPasswordDao dao;

    @Override
    public UserPasswordModel getUserPassword(String username, String password) {
        return dao.getUserPassword(username,password);
    }

    @Override
    public int addUser(UserPasswordModel model) {
        return dao.addUser(model) == 1 ? model.getIndex() : -1;
    }

    @Override
    public boolean changePassword(UserPasswordModel model, String new_password) {
        int result = dao.updateUser(model,new_password);
        return result == 1;
    }
}
