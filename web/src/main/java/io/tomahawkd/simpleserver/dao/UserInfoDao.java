package io.tomahawkd.simpleserver.dao;

import io.tomahawkd.simpleserver.model.UserInfoModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserInfoDao {
    //查询获取用户信息
    @Select("select * from user_info where username=#{username}")
    @Results({
            @Result(property = "index",column = "index"),
            @Result(property = "username",column = "username"),
            @Result(property = "name",column = "name"),
            @Result(property = "sex",column = "sex"),
            @Result(property = "email",column = "email"),
            @Result(property = "phone",column = "phone"),
            @Result(property = "bio",column = "bio"),
            @Result(property = "image_path",column = "image_path")
    })
    UserInfoModel getUserInfo(String username);

    //修改用户信息
    @Update("update user_info set name=#{model.name} and sex=#{model.sex} " +
            "and email=#{model.email} and phone=#{model.phone} and " +
            "bio=#{model.bio} and image_path=#{model.image_path}" +
            " where username=#{model.username}")
    int updateUserInfo(@Param("model") UserInfoModel model);
}
