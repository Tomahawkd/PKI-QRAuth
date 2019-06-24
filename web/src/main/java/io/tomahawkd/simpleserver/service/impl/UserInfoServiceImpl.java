package io.tomahawkd.simpleserver.service.impl;

import io.tomahawkd.simpleserver.dao.UserInfoDao;
import io.tomahawkd.simpleserver.model.UserInfoModel;
import io.tomahawkd.simpleserver.service.UserInfoService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserInfoServiceImpl implements UserInfoService {

	@Resource
	private UserInfoDao dao;

	@Override
	public UserInfoModel getUserInfo(String username) {
		return dao.getUserInfo(username);
	}

	@Override
	public boolean changeUserInfo(UserInfoModel model) {
		int result = dao.updateUserInfo(model);
		return result == 1;
	}
}
