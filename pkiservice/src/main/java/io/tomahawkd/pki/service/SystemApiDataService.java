package io.tomahawkd.pki.service;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.SystemApiDataModel;

public interface SystemApiDataService {

	SystemApiDataModel getApiById(int systemId);

	// return system id
	int registerSystemApi() throws CipherErrorException;

	boolean checkApi(SystemApiDataModel data, String systemApi);
}
