package io.tomahawkd.simpleserver.service.impl.base;


import io.tomahawkd.simpleserver.dao.base.UserPasswordDao;
import io.tomahawkd.simpleserver.model.base.UserPasswordModel;
import io.tomahawkd.simpleserver.service.base.UserPasswordService;
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
	public boolean checkPassword(String username, String password) {
		UserPasswordModel model = dao.getUser(username);
		if (model == null) return false;

		return password.equals(model.getPassword());

	}

	@Override
	public int addUser(UserPasswordModel model) {
		return dao.addUser(model) == 1 ? model.getIndex() : -1;
	}

	@Override
	public boolean changePassword(UserPasswordModel model, String new_password) {
		int result = dao.updateUser(model, new_password);
		return result == 1;
	}
}
