package io.tomahawkd.simpleserver.service.impl;

import io.tomahawkd.simpleserver.dao.SystemApiDataDao;
import io.tomahawkd.simpleserver.model.SystemApiDataModel;
import io.tomahawkd.simpleserver.service.SystemApiDataService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.UUID;

@Service
@Transactional(rollbackFor = Exception.class)
public class SystemApiDataServiceImpl implements SystemApiDataService {

	@Resource
	private SystemApiDataDao dao;

	@Override
	public SystemApiDataModel getApiById(int systemId) {
		return dao.getApiDataById(systemId);
	}

	@Override
	public int registerSystemApi() {
		UUID uuid = UUID.randomUUID();
		SystemApiDataModel model = new SystemApiDataModel(uuid.toString());
		return dao.registerApi(model) == 1 ? model.getSystemId() : -1;
	}

	@Override
	public boolean checkApi(SystemApiDataModel data, String systemApi) {
		return data.getSystemApi().equals(systemApi);
	}
}
