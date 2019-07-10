package io.tomahawkd.simpleserver.service;

import io.tomahawkd.simpleserver.model.UserPasswordModel;

public interface UserPasswordService {

	boolean checkUserExistence(String username);

	int checkPassword(String username, String password);

	int addUser(UserPasswordModel model);

	boolean updateUserPassword(UserPasswordModel model, String new_password) throws Exception;

	void deleteUser(int index);
}
