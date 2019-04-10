package com.yb.security.oauth.server.repository;

import com.yb.security.oauth.server.model.UserInfo;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Description:
 * author biaoyang
 * date 2019/4/8 000819:19
 */
public interface UserInfoRepository extends MongoRepository<UserInfo,String> {

    /**
     * 根据用户名查询用户信息--设定用户名唯一
     * @param username
     * @return
     */
    UserInfo findByUsername(String username);

}
