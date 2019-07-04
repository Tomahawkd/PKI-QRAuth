package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.QrStatusModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface QrStatusDao {

	@Insert("insert into qrcode_status (nonce, sym_key, iv, valid_by) values (#{qr.nonce}, #{qr.symKey}, #{qr.iv}," +
			"TIMESTAMPADD(MINUTE, 10, CURRENT_TIMESTAMP));")
	int addQrCode(@Param("qr") QrStatusModel status);

	@Update("update qrcode_status set token_id = #{token}, status = 1 where nonce = #{nonce}")
	int updateTokenToScanned(int token, int nonce);

	@Update("update qrcode_status set status = 2 where token_id = #{token}")
	int updateTokenToConfirmed(int token);

	@Delete("delete from qrcode_status where token_id = #{token}")
	int cleanAllStatus(int token);

	@Select("select token_id, nonce, sym_key, iv, status, valid_by from qrcode_status where nonce = #{nonce}")
	@Results({
			@Result(property = "tokenId", column = "token_id"),
			@Result(property = "nonce", column = "nonce"),
			@Result(property = "symKey", column = "sym_key"),
			@Result(property = "iv", column = "iv"),
			@Result(property = "status", column = "status"),
			@Result(property = "validBy", column = "valid_by")
	})
	QrStatusModel getByNonce(int nonce);
}
