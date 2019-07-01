package io.tomahawkd.pki.service;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.SystemKeyModel;

public interface SystemKeyService {

	SystemKeyModel getById(int systemId);

	// return system id
	int registerSystemApi() throws CipherErrorException;

	SystemKeyModel getByApi(String systemApi);
}
