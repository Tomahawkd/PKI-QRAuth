package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.KeyDistributionDao;
import io.tomahawkd.pki.service.KeyDistributionService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
@Transactional(rollbackFor = Exception.class)
public class KeyDistributionServiceImpl implements KeyDistributionService {

	@Resource
	private KeyDistributionDao dao;

	@Override
	public String getPublicKeyById(String id) {
		return dao.getPublicKeyById(id);
	}
}
