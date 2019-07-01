package io.tomahawkd.pki.service;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.SystemKeyModel;

public interface SystemKeyService {

	SystemKeyModel getApiById(int systemId);

	// return system id
	int registerSystemApi() throws CipherErrorException;

	boolean checkApi(SystemKeyModel data, String systemApi);

	SystemKeyModel getIdByApi(String systemApi);
}
