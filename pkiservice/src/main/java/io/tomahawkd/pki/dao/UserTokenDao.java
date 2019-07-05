package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.TokenModel;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface UserTokenDao {

	@Select("select `token_id`, `user_id`, `init_date`, `valid_by`, `nonce`, `device`, `ip`" +
			"from user_token where token_id = #{id}")
	@Results({
			@Result(property = "tokenId", column = "token_id"),
			@Result(property = "userId", column = "user_id"),
			@Result(property = "createDate", column = "init_date"),
			@Result(property = "validBy", column = "valid_by"),
			@Result(property = "nonce", column = "nonce"),
			@Result(property = "device", column = "device"),
			@Result(property = "ip", column = "ip")
	})
	TokenModel getByTokenId(@Param("id") int tokenId);

	@Select("select `token_id`, `user_id`, `init_date`, `valid_by`, `nonce`, `device`, `ip`" +
			"from user_token where user_id = #{id}")
	@Results({
			@Result(property = "tokenId", column = "token_id"),
			@Result(property = "userId", column = "user_id"),
			@Result(property = "createDate", column = "init_date"),
			@Result(property = "validBy", column = "valid_by"),
			@Result(property = "nonce", column = "nonce"),
			@Result(property = "device", column = "device"),
			@Result(property = "ip", column = "ip")
	})
	List<TokenModel> getByUserId(@Param("id") int user);

	@Update("update user_token set nonce = nonce + 1 where token_id = #{id}")
	int updateNonce(@Param("id") int tokenId);

	@Insert("insert into user_token (`user_id`, `valid_by`, `nonce`, `device`, `ip`) " +
			"values (#{token.userId}, TIMESTAMPADD(DAY, 30, CURRENT_TIMESTAMP), " +
			"#{token.nonce}, #{token.device}, #{token.ip})")
	@Options(keyProperty = "tokenId", useGeneratedKeys = true)
	int initToken(@Param("token") TokenModel token);

	@Delete("delete from user_token where token_id = #{id} and user_id = #{user}")
	int deleteToken(@Param("id") int tokenId, @Param("user") int userId);

	@Delete("delete from user_token where user_id = #{id}")
	int deleteUserTokens(@Param("id") int id);
}
