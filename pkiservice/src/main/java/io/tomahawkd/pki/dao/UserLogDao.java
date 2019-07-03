package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.UserLogModel;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface UserLogDao {

	@Insert("insert into user_log (`user_id`, `system_id`, `ip`, `device`, `message`) " +
			"values (#{log.userId}, #{log.systemId}, #{log.ip}, #{log.device}, #{log.message})")
	int logUserActivity(@Param("log") UserLogModel log);

	@Select("select user_id, system_id, time, ip, device, message from user_log " +
			"where user_id = #{userId} and system_id = #{systemId};")
	@Results({
			@Result(property = "userId", column = "user_id"),
			@Result(property = "systemId", column = "system_id"),
			@Result(property = "time", column = "time"),
			@Result(property = "ip", column = "ip"),
			@Result(property = "device", column = "device"),
			@Result(property = "message", column = "message")
	})
	List<UserLogModel> getUserActivityById(int userId, int systemId);
}
