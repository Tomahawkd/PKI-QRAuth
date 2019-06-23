package io.tomahawkd.pki.model;

import com.google.gson.Gson;

import java.sql.Timestamp;

public class UserLogModel {

	private transient int userId;
	private transient int systemId;
	private Timestamp time;
	private String ip;
	private String device;
	private String message;

	public UserLogModel(int userId, int systemId, Timestamp time, String ip, String device, String message) {
		this.userId = userId;
		this.systemId = systemId;
		this.time = time;
		this.ip = ip;
		this.device = device;
		this.message = message;
	}

	public int getUserId() {
		return userId;
	}

	public int getSystemId() {
		return systemId;
	}

	public Timestamp getTime() {
		return time;
	}

	public String getIp() {
		return ip;
	}

	public String getDevice() {
		return device;
	}

	public String getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return new Gson().toJson(UserLogModel.class);
	}
}
