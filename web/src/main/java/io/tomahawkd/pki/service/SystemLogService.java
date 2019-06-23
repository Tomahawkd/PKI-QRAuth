package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.SystemLogModel;

public interface SystemLogService {
    boolean insertLogRecord(SystemLogModel module);
}
