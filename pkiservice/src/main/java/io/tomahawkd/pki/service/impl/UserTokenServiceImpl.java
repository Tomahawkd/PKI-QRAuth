package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserIndexDao;
import io.tomahawkd.pki.dao.UserTokenDao;
import io.tomahawkd.pki.model.TokenModel;
import io.tomahawkd.pki.service.UserTokenService;
import io.tomahawkd.pki.util.SecurityFunctions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserTokenServiceImpl implements UserTokenService {

	@Resource
	private UserTokenDao dao;
	@Resource
	private UserIndexDao indexDao;

	@Override
	public TokenModel generateNewToken(String userTag, int systemId, String device, String ip) {
		int userId = indexDao.getUserIdByTag(userTag, systemId);
		TokenModel model = new TokenModel(userId, SecurityFunctions.generateRandom(), device, ip);
		dao.initToken(model);
		model = dao.getByTokenId(model.getTokenId());

		return model;
	}

	@Override
	public TokenModel generateNewTokenViaQrCode(int userId, String device, String ip) {
		TokenModel model = new TokenModel(userId, SecurityFunctions.generateRandom(), device, ip);
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

		TokenModel model = dao.getByTokenId(token.getTokenId());

		if (model == null) return false;
		dao.updateNonce(model.getTokenId());

		if (token.getValidBy().before(new Date(System.currentTimeMillis()))) {
			dao.deleteUserTokens(token.getTokenId());
			return false;
		}

		return token.equals(model) && model.getNonce() + 1 == nonce;
	}

	@Override
	public List<Map<String, String>> getTokenListByUserId(int userId) throws IOException {
		List<TokenModel> list = dao.getByUserId(userId);
		List<Map<String, String>> result = new ArrayList<>();
		if (list == null) return result;

		for (TokenModel model : list) {
			result.add(model.toMap());
		}

		return result;
	}

	@Override
	public int deleteUserTokenById(int tokenId, int userId) {
		return dao.deleteToken(tokenId, userId);
	}
}
