package io.tomahawkd.pki.util;

public class ThreadContext {

	private static ThreadLocal<ThreadLocalData> timeResponseContext = new ThreadLocal<>();

	public static ThreadLocal<ThreadLocalData> getContext() {
		return timeResponseContext;
	}
}
