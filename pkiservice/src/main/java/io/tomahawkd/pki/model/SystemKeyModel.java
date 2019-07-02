package io.tomahawkd.pki.model;

import com.google.gson.annotations.SerializedName;

import java.security.KeyPair;
import java.sql.Timestamp;
import java.util.Base64;

public class SystemKeyModel {

	private transient int systemId;
	private transient int systemUserId;
	@SerializedName("api")
	private String systemApi;
	@SerializedName("date")
	private Timestamp registerDate;
	private transient String publicKey;
	private transient String privateKey;

	public SystemKeyModel(int systemUserId, String systemApi, KeyPair kp) {
		this.systemApi = systemApi;
		this.systemUserId = systemUserId;
		this.publicKey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
		this.privateKey = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
	}

	private SystemKeyModel(int systemId, int systemUserId, String systemApi,
	                      Timestamp registerDate, String publicKey, String privateKey) {
		this.systemId = systemId;
		this.systemUserId = systemUserId;
		this.systemApi = systemApi;
		this.registerDate = registerDate;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public int getSystemId() {
		return systemId;
	}

	public int getSystemUserId() {
		return systemUserId;
	}

	public String getSystemApi() {
		return systemApi;
	}

	public Timestamp getRegisterDate() {
		return registerDate;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	@Override
	public String toString() {
		return "SystemKeyModel{" +
				"systemApi='" + systemApi + '\'' +
				"registerDate=" + registerDate +
				'}';
	}
}
