package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.SystemUserModel;

public interface SystemUserService {

	int addSystemUser(String username, String password);

	SystemUserModel getSystemUserByUsername(String username, String password);
}
