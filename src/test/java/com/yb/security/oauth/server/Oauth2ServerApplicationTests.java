package com.yb.security.oauth.server;

import com.yb.security.oauth.server.model.UserInfo;
import com.yb.security.oauth.server.repository.UserInfoRepository;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class Oauth2ServerApplicationTests {

    @Autowired
    private UserInfoRepository userInfoRepository;

    @Test
    public void contextLoads() {
            //通过用户名获取用户信息
            UserInfo userInfo = userInfoRepository.findByUsername("admin");
        System.err.println(userInfo.toString());
    }

}
