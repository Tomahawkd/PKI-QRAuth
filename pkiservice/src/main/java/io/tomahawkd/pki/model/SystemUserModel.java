package io.tomahawkd.pki.model;

public class SystemUserModel {

	private int userId;
	private String username;
	private String password;

	public SystemUserModel(String username, String password) {
		this.userId = -1;
		this.username = username;
		this.password = password;
	}

	public int getUserId() {
		return userId;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	@Override
	public String toString() {
		return "SystemUserModel{" +
				"userId=" + userId +
				", username='" + username + '\'' +
				", password='" + password + '\'' +
				'}';
	}
}
