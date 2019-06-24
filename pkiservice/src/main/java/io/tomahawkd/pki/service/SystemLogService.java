package io.tomahawkd.pki.service;

public interface SystemLogService {
    public boolean insertLogRecord(String module, String function, int level, String message);
}
