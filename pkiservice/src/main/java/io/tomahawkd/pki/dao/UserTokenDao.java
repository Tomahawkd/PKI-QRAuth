package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.TokenModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserTokenDao {

	@Select("select `token_id`, `user_id`, `system_id`, `init_date`, `valid_by`" +
			"from user_token where token_id = #{id}")
	@Results({
			@Result(property = "tokenId", column = "token_id"),
			@Result(property = "userId", column = "user_id"),
			@Result(property = "systemId", column = "system_id"),
			@Result(property = "createDate", column = "init_date"),
			@Result(property = "validBy", column = "valid_by")
	})
	TokenModel getById(@Param("id") int userId);

	@Insert("insert into user_token (`user_id`, `system_id`, `valid_by`) " +
			"values (#{token.userId}, #{token.systemId}, TIMESTAMPADD(DAY, 30, CURRENT_TIMESTAMP))")
	@Options(keyProperty = "tokenId", keyColumn = "token_id", useGeneratedKeys = true)
	int addToken(@Param("token") TokenModel token);

	@Delete("delete from user_token where token_id = #{id}")
	int deleteToken(@Param("id") int id);
}
