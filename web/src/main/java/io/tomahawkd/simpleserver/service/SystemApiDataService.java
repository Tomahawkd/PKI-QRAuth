package io.tomahawkd.simpleserver.service;

import io.tomahawkd.simpleserver.model.SystemApiDataModel;

public interface SystemApiDataService {

	SystemApiDataModel getApiById(int systemId);

	// return system id
	int registerSystemApi();

	boolean checkApi(SystemApiDataModel data, String systemApi);
}
