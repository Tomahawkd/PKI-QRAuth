package io.tomahawkd.pki.dao;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserIndexDao {

	@Select("select user_id from user_id_tag where user_tag = #{tag} and system_id = #{system} limit 0,1")
	int getUserIdByTag(String tag, int system);

	@Select("select user_tag from user_id_tag where user_id = #{id} limit 0,1")
	String getUserTagById(int id);
}
