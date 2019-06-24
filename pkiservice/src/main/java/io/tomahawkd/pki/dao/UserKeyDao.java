package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.UserKeyModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserKeyDao {

	@Select("select user_index, system_index, public_key, private_key from user_key " +
			"where user_index = #{userId} and system_index = #{systemId} limit 0,1")
	@Results({
			@Result(property = "userId", column = "user_index"),
			@Result(property = "systemId", column = "system_index"),
			@Result(property = "publicKey", column = "public_key"),
			@Result(property = "privateKey", column = "private_key")
	})
	UserKeyModel getUserKeyDataById(int userId, int systemId);

	@Insert("insert into user_key (user_index, system_index, public_key, private_key) " +
			"values (#{user.userId}, #{user.systemId}, #{user.publicKey}, #{user.privateKey})")
	void addUserKey(@Param("user") UserKeyModel user);

	@Update("update user_key set public_key = #{user.publicKey}," +
			"private_key = #{user.privateKey} " +
			"where user_index = #{user.userId} and system_index = #{user.systemId}")
	void updateUserKey(@Param("user") UserKeyModel user);
}
