package io.tomahawkd.pki.model;

import java.sql.Timestamp;

public class SystemApiDataModel {

	private int systemId;
	private String systemApi;
	private Timestamp registerDate;

	public SystemApiDataModel(String systemApi) {
		this.systemApi = systemApi;
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

	@Override
	public String toString() {
		return "SystemApiDataModel{" +
				"systemId=" + systemId +
				", systemApi='" + systemApi + '\'' +
				", registerDate=" + registerDate +
				'}';
	}
}
