package io.tomahawkd.simpleserver.service.impl;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.tomahawkd.simpleserver.dao.UserKeyDao;
import io.tomahawkd.simpleserver.exceptions.api.CipherErrorException;
import io.tomahawkd.simpleserver.model.UserKeyModel;
import io.tomahawkd.simpleserver.service.UserKeyService;
import io.tomahawkd.simpleserver.service.util.SecurityFunctions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.security.Key;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

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
		String user = systemId + "#" + userId;
		String secureString = SecurityFunctions.generateSecretByName(user);

		UserKeyModel model = generateKeysFor(userId, systemId);

		Map<String, Object> payloadMap = new HashMap<>();
		payloadMap.put("private", SecurityFunctions.securePrivateKey(user, random, model.getPrivateKey()));
		payloadMap.put("random", random);

		byte[] keyBytes = SecurityFunctions.generateSymKey(random);
		if (keyBytes == null) throw new CipherErrorException(new NullPointerException("Empty key"));

		Key key = Keys.hmacShaKeyFor(keyBytes);
		return Jwts.builder().setClaims(payloadMap).signWith(key).compact();
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
