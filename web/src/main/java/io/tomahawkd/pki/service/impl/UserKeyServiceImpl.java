package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.UserKeyDao;
import io.tomahawkd.pki.model.UserKeyModel;
import io.tomahawkd.pki.service.UserKeyService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.security.*;
import java.util.Base64;

@Service
@Transactional(rollbackFor = Exception.class)
public class UserKeyServiceImpl implements UserKeyService {

	@Resource
	private UserKeyDao dao;

	@Override
	public void generateKeysFor(int userId, int systemId) throws NoSuchAlgorithmException {
		// generate keys
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair kp = generator.generateKeyPair();
		String pubkey = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
		String prikey = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
		UserKeyModel model = new UserKeyModel(userId, systemId, pubkey, prikey);

		if (dao.getUserKeyDataById(userId, systemId) != null) dao.updateUserKey(model);
		else dao.addUserKey(model);
	}

	@Override
	public UserKeyModel getKeyById(int userId, int systemId) {
		return dao.getUserKeyDataById(userId, systemId);
	}
}
