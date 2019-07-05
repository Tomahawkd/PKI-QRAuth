package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserLogDao;
import io.tomahawkd.pki.model.UserLogModel;
import io.tomahawkd.pki.service.UserLogService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserLogServiceImpl implements UserLogService {

	@Resource
	private UserLogDao dao;

	@Override
	public List<UserLogModel> getUserActivitiesById(int userId, int systemId) {
		List<UserLogModel> logs = dao.getUserActivityById(userId, systemId);
		if (logs == null) return new ArrayList<>();
		return logs;
	}

	@Override
	public void insertUserActivity(int userId, int systemId, String device, String ip, String message) {
		UserLogModel log = new UserLogModel(userId, systemId, ip, device, message);
		dao.logUserActivity(log);
	}
}
