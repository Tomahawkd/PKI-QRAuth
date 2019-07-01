package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.SystemUserDao;
import io.tomahawkd.pki.model.SystemUserModel;
import io.tomahawkd.pki.service.SystemUserService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
@Transactional(rollbackFor = Exception.class)
public class SystemUserServiceImpl implements SystemUserService {

	@Resource
	private SystemUserDao dao;

	@Override
	public int addSystemUser(String username, String password) {
		return dao.addSystemUser(new SystemUserModel(username, password));
	}

	@Override
	public SystemUserModel getSystemUserByUsername(String username, String password) {
		return dao.getSystemUserByUsername(new SystemUserModel(username, password));
	}
}
