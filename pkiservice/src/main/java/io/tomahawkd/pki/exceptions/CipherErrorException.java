package io.tomahawkd.pki.exceptions;

public class CipherErrorException extends Exception {

	public CipherErrorException(Throwable cause) {
		super(cause);
	}

	public CipherErrorException(String message) {
		super(message);
	}
}
