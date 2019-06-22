package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserLogDao;
import io.tomahawkd.pki.model.UserLogModel;
import io.tomahawkd.pki.service.UserLogService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.List;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserLogServiceImpl implements UserLogService {

	@Resource
	private UserLogDao dao;

	@Override
	public String getUserActivitiesById(int userId, int systemId) {
		List<UserLogModel> list = dao.getUserActivityById(userId, systemId);
		if (list.size() == 0) return "[]";
		else {
			StringBuilder builder = new StringBuilder("[");
			list.forEach(e -> builder.append(e.toString()).append(","));
			builder.delete(builder.length()-2, builder.length()-1);
			return builder.append("]").toString();
		}
	}
}
