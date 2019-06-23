package io.tomahawkd.simpleserver.service;

import io.tomahawkd.simpleserver.exceptions.api.CipherErrorException;
import io.tomahawkd.simpleserver.model.UserKeyModel;

public interface UserKeyService {

	public String createKeyForm(int userId, int systemId, String random) throws CipherErrorException;

	UserKeyModel getKeyFormById(int userId, int systemId);
}
