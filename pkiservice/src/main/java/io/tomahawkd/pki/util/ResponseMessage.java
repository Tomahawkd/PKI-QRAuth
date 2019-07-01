package io.tomahawkd.pki.util;

public class ResponseMessage {

	private int status;
	private String message;

	public ResponseMessage(int status, String message) {
		this.status = status;
		this.message = message;
	}

	public void setOK() {
		this.status = 0;
	}

	public void setError() {
		this.status = 1;
	}

	public void setMessage(String message) {
		this.message = message;
	}
}
