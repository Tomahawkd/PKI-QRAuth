package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.UserKeyModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserKeyDao {

	@Select("select user_id, system_id, public_key, private_key from user_key " +
			"where user_id = #{userId} and system_id = #{systemId} limit 0,1")
	@Results({
			@Result(property = "userId", column = "user_id"),
			@Result(property = "systemId", column = "system_id"),
			@Result(property = "publicKey", column = "public_key"),
			@Result(property = "privateKey", column = "private_key")
	})
	UserKeyModel getUserKeyDataById(int userId, int systemId);

	@Insert("insert into user_key (user_id, system_id, public_key, private_key) " +
			"values (#{user.userId}, #{user.systemId}, #{user.publicKey}, #{user.privateKey})")
	void addUserKey(@Param("user") UserKeyModel user);

	@Delete("delete from user_key " +
			"where user_id = #{user.userId} and system_id = #{user.systemId}")
	void deleteUserKey(@Param("user") UserKeyModel user);
}
