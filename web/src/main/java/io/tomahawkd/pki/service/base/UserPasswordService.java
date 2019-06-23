package io.tomahawkd.pki.service.base;

import io.tomahawkd.pki.model.base.UserPasswordModel;

public interface UserPasswordService {
    boolean checkPassword(String username,String password,String random);
    int addUser(UserPasswordModel model);
    boolean changePassword(UserPasswordModel model,String new_password) throws Exception;
}
