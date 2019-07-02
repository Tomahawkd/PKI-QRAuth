package io.tomahawkd.pki.api.client.util;

public class ResponseMessage {

	private int status;
	private String message;

	public ResponseMessage(int status, String message) {
		this.status = status;
		this.message = message;
	}

	public ResponseMessage setOK() {
		this.status = 0;
		return this;
	}

	public ResponseMessage setError() {
		this.status = 1;
		return this;
	}

	public void setMessage(String message) {
		this.message = message;
	}
}
