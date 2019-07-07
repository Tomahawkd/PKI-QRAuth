package io.tomahawkd.pki.service;

import io.tomahawkd.pki.model.TokenModel;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public interface UserTokenService {

	TokenModel generateNewToken(String userTag, int systemId, String device, String ip);

	TokenModel generateNewTokenViaQrCode(int userId, String device, String ip);

	TokenModel getTokenById(int tokenId);

	boolean validateToken(TokenModel token, int nonce);

	List<Map<String, String>> getTokenListByUserId(int userId) throws IOException;

	int deleteUserTokenById(int tokenId, int userId);
}
