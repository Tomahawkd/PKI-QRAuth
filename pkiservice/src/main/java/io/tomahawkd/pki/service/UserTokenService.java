package io.tomahawkd.pki.service;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.model.TokenModel;

public interface UserTokenService {

	byte[] generateNewToken(String userTag, int systemId) throws CipherErrorException;

	TokenModel getTokenById(int tokenId);
}
