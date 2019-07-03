package io.tomahawkd.pki.service;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.UserKeyModel;

public interface UserKeyService {

	UserKeyModel generateKeysFor(String userTag, int systemId) throws CipherErrorException;

	UserKeyModel getUserByTagAndSystem(String userTag, int systemId);

	UserKeyModel regenerateKeysAndDeleteTokenFor(int userId) throws CipherErrorException;

	UserKeyModel getUserById(int userId);
}
