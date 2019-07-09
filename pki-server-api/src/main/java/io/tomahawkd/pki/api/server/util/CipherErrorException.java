package io.tomahawkd.pki.api.server.util;

public class CipherErrorException extends RuntimeException {

	public CipherErrorException(Throwable cause) {
		super(cause);
	}

	public CipherErrorException(String message) {
		super(message);
	}
}
