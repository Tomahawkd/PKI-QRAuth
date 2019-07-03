package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserKeyDao;
import io.tomahawkd.pki.dao.UserTokenDao;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.UserKeyModel;
import io.tomahawkd.pki.service.UserKeyService;
import io.tomahawkd.pki.util.SecurityFunctions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.security.KeyPair;
import java.util.Base64;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserKeyServiceImpl implements UserKeyService {

	@Resource
	private UserKeyDao dao;
	@Resource
	private UserTokenDao tokenDao;

	@Override
	public UserKeyModel getUserByTagAndSystem(String userTag, int systemId) {
		return dao.getUserKeyDataById(userTag, systemId);
	}

	public UserKeyModel generateKeysFor(String userTag, int systemId) throws CipherErrorException {
		// generate keys
		KeyPair kp = SecurityFunctions.generateKeyPair();
		String pubkey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
		String prikey = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
		UserKeyModel model = new UserKeyModel(systemId, userTag, pubkey, prikey);

		dao.addUserKey(model);

		return model;
	}

	@Override
	public UserKeyModel regenerateKeysAndDeleteTokenFor(int userId) throws CipherErrorException {
		KeyPair kp = SecurityFunctions.generateKeyPair();
		String pubkey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
		String prikey = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
		UserKeyModel model = new UserKeyModel(userId, pubkey, prikey);

		tokenDao.deleteUserTokens(userId);
		dao.updateUserKey(model);

		return model;
	}

	@Override
	public UserKeyModel getUserById(int userId) {
		return dao.getUserById(userId);
	}
}
