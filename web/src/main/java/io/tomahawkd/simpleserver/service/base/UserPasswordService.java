package io.tomahawkd.simpleserver.service.base;

import io.tomahawkd.simpleserver.model.base.UserPasswordModel;

public interface UserPasswordService {

	boolean checkUserExistence(String username);

	boolean checkPassword(String username, String password);

	int addUser(UserPasswordModel model);

	boolean changePassword(UserPasswordModel model, String new_password) throws Exception;
}
