package io.tomahawkd.pki.util;

import io.tomahawkd.pki.service.SystemLogService;

public class ThreadContext {

	private static ThreadLocal<String> timeResponseContext = new ThreadLocal<>();
	private static ThreadLocal<SystemLogService> logContext = new ThreadLocal<>();

	public static ThreadLocal<String> getTimeContext() {
		return timeResponseContext;
	}

	public static ThreadLocal<SystemLogService> getLogContext() {
		return logContext;
	}
}
