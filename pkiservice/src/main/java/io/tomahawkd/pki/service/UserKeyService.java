package io.tomahawkd.pki.service;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.UserKeyModel;

public interface UserKeyService {

	public String createKeyForm(int userId, int systemId, String random) throws CipherErrorException;

	UserKeyModel getKeyFormById(int userId, int systemId);
}
