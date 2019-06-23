package io.tomahawkd.pki.service.base;

import io.tomahawkd.pki.model.base.UserPasswordModel;

public interface UserPasswordService {
    UserPasswordModel getUserPassword(String username,String password);
    int addUser(UserPasswordModel model);
    boolean changePassword(UserPasswordModel model,String new_password) throws Exception;
}
