package io.tomahawkd.pki.model;

import java.sql.Timestamp;

public class UserLogModel {

	private int userId;
	private int systemId;
	private Timestamp time;
	private String ip;
	private String device;
	private String message;

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
		return "{" +
				"\"time\": \"" + time + "\", " +
				"\"ip\": \"" + ip + "\", " +
				"\"device\": \"" + device + "\", " +
				"\"message\": " + message + "\", " +
				'}';
	}
}
