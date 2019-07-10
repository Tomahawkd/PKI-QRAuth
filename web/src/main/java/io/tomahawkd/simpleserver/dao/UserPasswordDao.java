package io.tomahawkd.simpleserver.dao;

import io.tomahawkd.simpleserver.model.UserPasswordModel;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserPasswordDao {
    //用户登录
    @Select("select `index`,username,password from user_info where userid=#{userid}")
    @Results({
            @Result(property = "index", column = "index"),
            @Result(property = "username",column = "username"),
            @Result(property = "password",column = "password")
    })
    UserPasswordModel getUser(int userid);

    //添加新用户
    @Insert("insert into user_info(username,password) values (#{model.username},#{model.password})")
    @Options(keyProperty = "index",useGeneratedKeys = true)
    int addUser(@Param("model") UserPasswordModel model);

    //用户修改密码
    @Update("update user_info set password=#{new_password} where userid=#{model.userid} and password=#{model.password}")
    int updateUserPassword(@Param("model") UserPasswordModel model,String new_password);

    //删除用户
    @Delete("delete from user_info where `index`=#{userid}")
    void deleteUser(int userid);



}
