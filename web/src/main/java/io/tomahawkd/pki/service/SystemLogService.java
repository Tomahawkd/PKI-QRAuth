package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.SystemLogModel;

public interface SystemLogService {
    public boolean insertLogRecord(String module, String function, int level, String message);
}
