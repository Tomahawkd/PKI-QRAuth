package io.tomahawkd.pki.util;

import io.tomahawkd.pki.service.SystemLogService;

public class ThreadLocalData {

	private SystemLogService log;
	private String time;

	public ThreadLocalData(SystemLogService log, String time) {
		this.log = log;
		this.time = time;
	}

	public SystemLogService getLog() {
		return log;
	}

	public String getTime() {
		return time;
	}
}
