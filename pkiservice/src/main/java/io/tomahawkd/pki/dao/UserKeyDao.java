package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.UserKeyModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserKeyDao {

	@Select("select user_id, system_id, public_key, private_key from user_key " +
			"where user_tag = #{tag} and system_id = #{system} limit 0,1")
	@Results({
			@Result(property = "userId", column = "user_id"),
			@Result(property = "systemId", column = "system_id"),
			@Result(property = "userTag", column = "user_tag"),
			@Result(property = "publicKey", column = "public_key"),
			@Result(property = "privateKey", column = "private_key")
	})
	UserKeyModel getUserKeyDataById(@Param("tag") String userId, @Param("system") int systemId);

	@Insert("insert into user_key (system_id, user_tag, public_key, private_key) " +
			"values (#{user.systemId}, #{user.userTag}, #{user.publicKey}, #{user.privateKey})")
	@Options(keyProperty = "userId", useGeneratedKeys = true)
	int addUserKey(@Param("user") UserKeyModel user);

	@Update("update user_key set public_key = #{user.publicKey}, " +
			"private_key = #{user.privateKey} " +
			"where user_id = #{user.userId}")
	int updateUserKey(@Param("user") UserKeyModel user);
}
