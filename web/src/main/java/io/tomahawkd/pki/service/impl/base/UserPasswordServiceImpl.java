package io.tomahawkd.pki.service.impl.base;


import io.tomahawkd.pki.dao.base.UserPasswordDao;
import io.tomahawkd.pki.model.base.UserPasswordModel;
import io.tomahawkd.pki.service.base.UserPasswordService;
import org.apache.catalina.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserPasswordServiceImpl implements UserPasswordService {
    @Resource
    private UserPasswordDao dao;

    @Override
    public boolean checkUserExistence(String username) {
        UserPasswordModel model = dao.getUser(username);
        return model != null;
    }

    @Override
    public boolean checkPassword(String username, String password,String random) {
        UserPasswordModel model = dao.getUser(username);
        String new_password = f(model.getPassword(), random);
        return password.equals(new_password);

    }

    private String f(String password,String random){    //f(t)
        return password + random;
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
