package io.tomahawkd.pki.api.server.util;

public class MalformedJsonException extends Exception {

	public MalformedJsonException(String message) {
		super(message);
		System.out.println(message);
	}
}
