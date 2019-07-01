package io.tomahawkd.pki.dao;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserIndexDao {

	@Select("select user_id from user_id_tag where user_tag = #{tag}")
	int getUserIdByTag(String tag);

	@Select("select user_tag from user_id_tag where user_id = #{id}")
	String getUserTagById(int id);
}
