package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.SystemKeyDao;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.SystemKeyModel;
import io.tomahawkd.pki.service.SystemKeyService;
import io.tomahawkd.pki.util.SecurityFunctions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.List;
import java.util.UUID;

@Service
@Transactional(rollbackFor = Exception.class)
public class SystemKeyServiceImpl implements SystemKeyService {

	@Resource
	private SystemKeyDao dao;

	@Override
	public SystemKeyModel getById(int systemId) {
		return dao.getApiDataById(systemId);
	}

	@Override
	public SystemKeyModel getByApi(String systemApi) {
		return dao.getIdByApiData(systemApi);
	}

	@Override
	public List<SystemKeyModel> getByUser(int userId) {
		return dao.getByUser(userId);
	}

	@Override
	public int registerSystemApi(int userId) throws CipherErrorException {
		UUID uuid = UUID.randomUUID();
		SystemKeyModel model = new SystemKeyModel(userId, uuid.toString(), SecurityFunctions.generateKeyPair());
		return dao.registerApi(model) == 1 ? model.getSystemId() : -1;
	}
}
