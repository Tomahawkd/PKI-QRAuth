package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.UserKeyModel;

import java.security.NoSuchAlgorithmException;

public interface UserKeyService {

	void generateKeysFor(int userId, int systemId) throws NoSuchAlgorithmException;

	UserKeyModel getKeyById(int userId, int systemId);
}
