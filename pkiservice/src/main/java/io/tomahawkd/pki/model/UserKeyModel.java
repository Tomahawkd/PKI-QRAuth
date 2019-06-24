package io.tomahawkd.pki.model;

public class UserKeyModel {

	private int userId;
	private int systemId;
	private String publicKey;
	private String privateKey;

	public UserKeyModel(int userId, int systemId, String publicKey, String privateKey) {
		this.userId = userId;
		this.systemId = systemId;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public int getUserId() {
		return userId;
	}

	public int getSystemId() {
		return systemId;
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
