package io.tomahawkd.pki.util;

public class ThreadContext {

	private static ThreadLocal<String> timeResponseContext = new ThreadLocal<>();

	public static ThreadLocal<String> getContext() {
		return timeResponseContext;
	}
}
