package com.yb.security.oauth.server.controller;

import com.yb.security.oauth.server.model.UserInfo;
import com.yb.security.oauth.server.repository.UserInfoRepository;
import org.hibernate.validator.constraints.Length;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.validation.constraints.NotBlank;
import java.security.Principal;

/**
 * Description:
 * author biaoyang
 * date 2019/4/8 000819:21
 */
@RestController
@CrossOrigin
@Validated
public class UserInfoController {

    private final UserInfoRepository userInfoRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public UserInfoController(UserInfoRepository userInfoRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userInfoRepository = userInfoRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    /**
     * 初始化账户信息
     * spring容器会在类加载后自动注入这个方法的参数,执行一遍,这就像static{}块语句了,但顺序不一样
     * 这个跟直接写@Autowired private UserInfo userInfo;是一样的,只是那个只是用无参构造实例化了一个对象,这里做了更多的事情
     */
    @Autowired
    public void init() {
        // 为了方便测试,这里添加了两个不同角色的账户
        userInfoRepository.deleteAll();

        UserInfo userInfoA = new UserInfo();
        userInfoA.setUsername("admin");
        //为密码加密
        userInfoA.setPassword(bCryptPasswordEncoder.encode("admin"));
        userInfoA.setRoles(new String[]{"ROLE_ADMIN", "ROLE_USER"});
        userInfoRepository.save(userInfoA);

    }

    /**
     * 根据用户名获取用户信息
     *
     * @param username
     * @return
     */
    @PreAuthorize("hasRole('aa')")//已验证合法性后可访问
    @GetMapping("findByUsername")
    public UserInfo findByUsername(
            @NotBlank(message = "用户名不能为空")
            @Length(max = 20, message = "用户名有误")
            @RequestParam String username) {
        //设定用户名唯一
        UserInfo result = userInfoRepository.findByUsername(username);
        return result;
    }

    /**
     * 获取授权用户信息
     *
     * @param user 当前用户
     * @return 授权信息
     */
    @GetMapping("/user")
    public Principal user(Principal user) {
        System.err.println("哎呦,不错哦");
        return user;
    }

}
