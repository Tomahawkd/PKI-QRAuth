package io.tomahawkd.pki.model;

import com.google.gson.annotations.SerializedName;

public class UserKeyModel {

	private transient int userId;
	@SerializedName("system")
	private int systemId;
	@SerializedName("user")
	private String userTag;
	private transient String publicKey;
	private transient String privateKey;

	public UserKeyModel(int userId, String publicKey, String privateKey) {
		this.userId = userId;
		this.systemId = -1;
		this.userTag = "";
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public UserKeyModel(int systemId, String userTag, String publicKey, String privateKey) {
		this.userId = -1;
		this.systemId = systemId;
		this.userTag = userTag;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public int getUserId() {
		return userId;
	}

	public int getSystemId() {
		return systemId;
	}

	public String getUserTag() {
		return userTag;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	@Override
	public String toString() {
		return "UserKeyModel{" +
				"userId=" + userId +
				", systemId=" + systemId +
				", publicKey='" + publicKey + '\'' +
				", privateKey='" + privateKey + '\'' +
				'}';
	}
}
