package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.QrStatusModel;

public interface QrStatusService {

	QrStatusModel generateQrNonce(String symKey, String iv);
}
