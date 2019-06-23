package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.SystemLogDao;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.service.SystemLogService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service()
@Transactional(rollbackFor = Exception.class)
public class SystemLogServiceImpl implements SystemLogService {

    @Resource
    private SystemLogDao dao;

    @Override
    public boolean insertLogRecord(String module, String function, int level, String message) {
        String m = module + "#" + function;
        int result = dao.insertLogRecord(new SystemLogModel(m, level, message));
        return result == 1;
    }
}

