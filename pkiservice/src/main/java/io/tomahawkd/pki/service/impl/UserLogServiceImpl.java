package io.tomahawkd.pki.service.impl;

import com.google.gson.Gson;
import io.tomahawkd.pki.dao.UserLogDao;
import io.tomahawkd.pki.service.UserLogService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserLogServiceImpl implements UserLogService {

	@Resource
	private UserLogDao dao;

	@Override
	public String getUserActivitiesById(int userId, int systemId) {
		return new Gson().toJson(dao.getUserActivityById(userId, systemId));
	}
}
