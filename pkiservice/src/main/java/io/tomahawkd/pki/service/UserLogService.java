package io.tomahawkd.pki.service;

public interface UserLogService {

	String getUserActivitiesById(int userId, int systemId);

	void insertUserActivity(int userId, int systemId, String device, String ip, String message);
}
