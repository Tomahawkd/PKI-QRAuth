package io.tomahawkd.pki.service;

import javax.servlet.http.HttpServletRequest;

public interface SystemLogService {

    boolean insertLogRecord(String module, String function, int level, String message);

    void addAccessLog(String module, String function, String ip, String ua);
}
