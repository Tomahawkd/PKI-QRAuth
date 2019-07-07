package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.UserLogModel;

import java.util.List;

public interface UserLogService {

	List<UserLogModel> getUserActivitiesById(int userId, int systemId);

	void insertUserActivity(int userId, int systemId, String device, String ip, String message);
}
