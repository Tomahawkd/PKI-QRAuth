package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserKeyDao;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.UserKeyModel;
import io.tomahawkd.pki.service.UserKeyService;
import io.tomahawkd.pki.service.util.SecurityFunctions;
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

	@Override
	public UserKeyModel getKeyFormById(int userId, int systemId) {
		return dao.getUserKeyDataById(userId, systemId);
	}

	@Override
	public String createKeyForm(int userId, int systemId, String random)
			throws CipherErrorException {
		return "";
	}

	private UserKeyModel generateKeysFor(int userId, int systemId) throws CipherErrorException {
		// generate keys
		KeyPair kp = SecurityFunctions.generateKeyPair();
		String pubkey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
		String prikey = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
		UserKeyModel model = new UserKeyModel(userId, systemId, pubkey, prikey);

		if (dao.getUserKeyDataById(userId, systemId) != null) dao.updateUserKey(model);
		else dao.addUserKey(model);

		return model;
	}
}
