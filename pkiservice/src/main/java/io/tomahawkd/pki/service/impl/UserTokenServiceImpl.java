package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserIndexDao;
import io.tomahawkd.pki.dao.UserTokenDao;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.TokenModel;
import io.tomahawkd.pki.service.UserTokenService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserTokenServiceImpl implements UserTokenService {

	@Resource
	private UserTokenDao dao;
	@Resource
	private UserIndexDao indexDao;

	@Override
	public byte[] generateNewToken(String userTag, int systemId) throws CipherErrorException {
		int userId = indexDao.getUserIdByTag(userTag);
		TokenModel model = new TokenModel(userId);
		dao.initToken(model);
		model = dao.getByTokenId(model.getTokenId());

		return model.serialize();
	}

	@Override
	public TokenModel getTokenById(int tokenId) {
		return dao.getByTokenId(tokenId);
	}
}
