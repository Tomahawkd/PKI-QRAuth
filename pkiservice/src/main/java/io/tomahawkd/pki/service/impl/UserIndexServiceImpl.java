package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserIndexDao;
import io.tomahawkd.pki.service.UserIndexService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserIndexServiceImpl implements UserIndexService {

	@Resource
	private UserIndexDao dao;

	@Override
	public int getUserIdByTag(String tag) {
		return dao.getUserIdByTag(tag);
	}

	@Override
	public String getUserTagById(int id) {
		return dao.getUserTagById(id);
	}
}
