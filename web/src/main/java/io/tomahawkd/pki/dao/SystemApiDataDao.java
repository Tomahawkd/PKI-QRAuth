package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.SystemApiDataModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface SystemApiDataDao {

	@Select("select system_index, system_api, register_date from system_api_index " +
			"where system_index = #{id} limit 0,1")
	@Results({
			@Result(property = "systemId", column = "system_index"),
			@Result(property = "systemApi", column = "system_api"),
			@Result(property = "registerDate", column = "register_date")
	})
	SystemApiDataModel getApiDataById(int id);

	@Insert("insert into system_api_index (`system_api`) values (#{api.systemApi})")
	@Options(keyProperty = "systemId", useGeneratedKeys = true)
	int registerApi(@Param("api") SystemApiDataModel api);
}
