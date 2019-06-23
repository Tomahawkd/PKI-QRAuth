package io.tomahawkd.simpleserver.dao;

import io.tomahawkd.simpleserver.model.UserLogModel;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface UserLogDao {

	@Insert("insert into user_log (`user_index`, `system_index`, `ip`, `device`, `message`) " +
			"values (#{log.userId}, #{log.systemId}, #{log.ip}, #{log.device}, #{log.message})")
	int logUserActivity(@Param("log") UserLogModel log);

	@Select("select user_index, system_index, time, ip, device, message from user_log " +
			"where user_index = #{userId} and system_index = #{systemId};")
	@Results({
			@Result(property = "userId", column = "user_index"),
			@Result(property = "systemId", column = "system_index"),
			@Result(property = "time", column = "time"),
			@Result(property = "ip", column = "ip"),
			@Result(property = "device", column = "device"),
			@Result(property = "message", column = "message")
	})
	List<UserLogModel> getUserActivityById(int userId, int systemId);
}
