package io.tomahawkd.pki.model;

import java.security.KeyPair;
import java.sql.Timestamp;
import java.util.Base64;

public class SystemApiDataModel {

	private int systemId;
	private String systemApi;
	private Timestamp registerDate;
	private String publicKey;
	private String privateKey;

	public SystemApiDataModel(String systemApi, KeyPair kp) {
		this.systemApi = systemApi;
		this.publicKey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
		this.privateKey = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
	}

	public int getSystemId() {
		return systemId;
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
		return "SystemApiDataModel{" +
				"systemId=" + systemId +
				", systemApi='" + systemApi + '\'' +
				", registerDate=" + registerDate +
				'}';
	}
}
