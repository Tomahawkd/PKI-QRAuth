package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.SystemApiDataModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface SystemApiDataDao {

	@Select("select system_id, system_api, register_date, public_key, private_key from system_api_index " +
			"where system_id = #{id} limit 0,1")
	@Results({
			@Result(property = "systemId", column = "system_id"),
			@Result(property = "systemApi", column = "system_api"),
			@Result(property = "registerDate", column = "register_date"),
			@Result(property = "publicKey", column = "public_key"),
			@Result(property = "privateKey", column = "private_key")
	})
	SystemApiDataModel getApiDataById(int id);

	@Insert("insert into system_api_index (`system_api`) values (#{api.systemApi})")
	@Options(keyProperty = "systemId", useGeneratedKeys = true)
	int registerApi(@Param("api") SystemApiDataModel api);
}
