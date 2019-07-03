package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.TokenModel;

public interface UserTokenService {

	TokenModel generateNewToken(String userTag, int systemId, String device, String ip);

	TokenModel generateNewTokenViaQrCode(int userId, String device, String ip);

	TokenModel getTokenById(int tokenId);

	boolean validateToken(TokenModel token, int nonce);
}
