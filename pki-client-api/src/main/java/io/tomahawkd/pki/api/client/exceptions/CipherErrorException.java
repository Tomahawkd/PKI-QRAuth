package io.tomahawkd.pki.api.client.exceptions;

public class CipherErrorException extends Exception {

	public CipherErrorException(Exception cause) {
		super(cause);
	}

	public CipherErrorException(String message) {
		super(message);
	}
}
