package com.yb.security.oauth.server.impl;

import com.yb.security.oauth.server.model.UserInfo;
import com.yb.security.oauth.server.repository.UserInfoRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Description:用户信息服务--实现 Spring Security的UserDetailsService接口方法,用于身份认证
 * author biaoyang
 * date 2019/4/8 000819:56
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Autowired
    private UserInfoRepository userInfoRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("UserDetailsServiceImpl==========loadUserByUsername(String username)");
        //通过用户名获取用户信息
        UserInfo userInfo = userInfoRepository.findByUsername(username);
        //判断用户是否存在
        if (userInfo != null) {
            return new User(userInfo.getUsername(), null, AuthorityUtils.createAuthorityList(userInfo.getRoles()));
        } else {
            //抛出异常中断程序
            throw new UsernameNotFoundException("用户名或密码错误");
        }
    }

}
