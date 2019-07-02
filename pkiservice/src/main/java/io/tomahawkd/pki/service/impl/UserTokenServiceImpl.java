package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserIndexDao;
import io.tomahawkd.pki.dao.UserTokenDao;
import io.tomahawkd.pki.model.TokenModel;
import io.tomahawkd.pki.service.UserTokenService;
import io.tomahawkd.pki.util.SecurityFunctions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.Date;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserTokenServiceImpl implements UserTokenService {

	@Resource
	private UserTokenDao dao;
	@Resource
	private UserIndexDao indexDao;

	@Override
	public TokenModel generateNewToken(String userTag, int systemId) {
		int userId = indexDao.getUserIdByTag(userTag);
		TokenModel model = new TokenModel(userId, SecurityFunctions.generateRandom());
		dao.initToken(model);
		model = dao.getByTokenId(model.getTokenId());

		return model;
	}

	@Override
	public TokenModel getTokenById(int tokenId) {
		return dao.getByTokenId(tokenId);
	}

	@Override
	public boolean validateToken(TokenModel token, int nonce) {

		return token.equals(dao.getByTokenId(token.getTokenId())) &&
				token.getValidBy().compareTo(new Date(System.currentTimeMillis())) < 0 &&
				token.getNonce() + 1 == nonce;
	}
}
