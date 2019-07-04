package io.tomahawkd.pki.service;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.SystemKeyModel;

import java.util.List;

public interface SystemKeyService {

	SystemKeyModel getById(int systemId);

	// return system id
	int registerSystemApi(int userId) throws CipherErrorException;

	SystemKeyModel getByApi(String systemApi);

	List<SystemKeyModel> getByUser(int userId);
}
