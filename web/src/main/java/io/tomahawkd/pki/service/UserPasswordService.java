package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.UserPasswordModel;

import java.util.List;

public interface UserPasswordService {
    UserPasswordModel getUserPassword(String username,String password);
    int addUser(UserPasswordModel model);
    boolean changePassword(UserPasswordModel model,String new_password) throws Exception;
}
