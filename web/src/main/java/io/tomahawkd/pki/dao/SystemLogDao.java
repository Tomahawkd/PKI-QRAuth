package io.tomahawkd.pki.dao;

import io.tomahawkd.pki.model.SystemLogModel;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface SystemLogDao {

    @Insert("INSERT INTO system_log (module,level,message) " +
            "VALUES (#{module.module}, #{module.level}, #{module.message})")
    int insertLogRecord(@Param("module") SystemLogModel module);
}
