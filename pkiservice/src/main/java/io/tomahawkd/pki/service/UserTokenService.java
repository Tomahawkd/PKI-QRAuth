package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.TokenModel;

public interface UserTokenService {

	boolean validateToken(String tokenData);

	TokenModel getToken(int tokenId);

	byte[] getSerializedToken(int tokenId);

	byte[] generateNewToken(int userId, int systemId);

	void revokeToken(int tokenId);
}
