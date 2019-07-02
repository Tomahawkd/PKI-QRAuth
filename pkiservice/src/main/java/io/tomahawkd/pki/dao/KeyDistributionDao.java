package io.tomahawkd.pki.dao;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface KeyDistributionDao {

	@Select("select `public_key` from system_api_view where system_api = #{id} limit 0,1;")
	String getPublicKeyById(String id);
}
