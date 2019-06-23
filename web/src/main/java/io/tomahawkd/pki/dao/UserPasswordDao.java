package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.model.UserPasswordModel;
import org.apache.ibatis.annotations.*;

import java.util.List;
@Mapper
public interface UserPasswordDao {
    //查用户登录
    @Select("select username,password from user_info where username=#{username} and password=#{password}")
    @Results({
            @Result(property = "username",column = "username"),
            @Result(property = "password",column = "password")
    })
    UserPasswordModel getUserPassword(String username,String password);

    //添加新用户
    @Insert("insert into user_info(username,password) values (#{model.username},#{model.password})")
    @Options(keyProperty = "index",useGeneratedKeys = true)
    int addUser(@Param("model") UserPasswordModel model);

    //用户修改密码
    @Update("update user_info set password=#{new_password} where username=#{model.username} and password=#{model.password}")
    int updateUser(@Param("model") UserPasswordModel model,String new_password);
}
