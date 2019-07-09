package io.tomahawkd.simpleserver.service.impl;


import io.tomahawkd.simpleserver.dao.UserPasswordDao;
import io.tomahawkd.simpleserver.model.UserPasswordModel;
import io.tomahawkd.simpleserver.service.UserPasswordService;
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
	public int checkPassword(String username, String password) {
		UserPasswordModel model = dao.getUser(username);
		if (model == null) return -1;

		return password.equals(model.getPassword()) ? model.getIndex() : -1;

	}

	@Override
	public int addUser(UserPasswordModel model) {
		return dao.addUser(model) == 1 ? model.getIndex() : -1;
	}

	@Override
	public boolean updateUserPassword(UserPasswordModel model, String new_password) {
		int result = dao.updateUserPassword(model, new_password);
		return result == 1;
	}

	@Override
	public  void deleteUser(int index){
		dao.deleteUser(index);
	}
}
