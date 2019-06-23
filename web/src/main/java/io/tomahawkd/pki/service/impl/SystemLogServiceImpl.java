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
    public boolean insertLogRecord(SystemLogModel module) {
        int result = dao.insertLogRecord(module);
        return result == 1;
    }
}

