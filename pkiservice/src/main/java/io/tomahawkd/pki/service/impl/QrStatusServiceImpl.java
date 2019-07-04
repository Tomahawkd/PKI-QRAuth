package io.tomahawkd.pki.service.impl;

import io.tomahawkd.pki.dao.QrStatusDao;
import io.tomahawkd.pki.model.QrStatusModel;
import io.tomahawkd.pki.service.QrStatusService;
import io.tomahawkd.pki.util.SecurityFunctions;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;

@Service
@Transactional(rollbackFor = Exception.class)
public class QrStatusServiceImpl implements QrStatusService {

	@Resource
	private QrStatusDao dao;

	@Override
	public QrStatusModel generateQrNonce(String symKey, String iv) {
		QrStatusModel model = new QrStatusModel(SecurityFunctions.generateRandom(), symKey, iv);
		dao.addQrCode(model);
		return model;
	}
}
