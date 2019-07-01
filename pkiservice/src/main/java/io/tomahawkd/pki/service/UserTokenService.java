package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.TokenModel;

public interface UserTokenService {

	byte[] generateNewToken(String userTag, int systemId);

	TokenModel getTokenById(int tokenId);

	boolean validateToken(TokenModel token, int nonce);
}
