package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.SystemUserModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface SystemUserDao {

	@Insert("insert into system_user (`username`, `password`) values (#{user.username}, #{user.password})")
	@Options(keyProperty = "userId", useGeneratedKeys = true)
	int addSystemUser(@Param("user") SystemUserModel user);


	@Select("select `system_user_id`, `username`, `password` " +
			"from system_user where username = #{user.username} and password = #{user.password}")
	@Results({
			@Result(property = "userId", column = "system_user_id"),
			@Result(property = "username", column = "username"),
			@Result(property = "password", column = "password")
	})
	SystemUserModel getSystemUserByUsername(@Param("user") SystemUserModel user);

}
