package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.QrStatusModel;

public interface QrStatusService {

	QrStatusModel generateQrNonce(String symKey, String iv);

	void updateQrNonceStatusToScanned(int tokenId, int nonce);

	void updateQrNonceStatusToConfirmed(int tokenId);

	void clearStatus(int tokenId);

	QrStatusModel getQrStatusByNonce(int nonce);
}
