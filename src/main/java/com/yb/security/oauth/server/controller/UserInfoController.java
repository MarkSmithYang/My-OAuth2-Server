package com.yb.security.oauth.server.controller;

import com.alibaba.fastjson.JSONObject;
import com.yb.security.oauth.server.dic.JwtDic;
import com.yb.security.oauth.server.model.LoginUser;
import com.yb.security.oauth.server.model.UserInfo;
import com.yb.security.oauth.server.repository.UserInfoRepository;
import com.yb.security.oauth.server.utils.JwtUtils;
import lombok.AllArgsConstructor;
import org.hibernate.validator.constraints.Length;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.constraints.NotBlank;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;

/**
 * Description:
 * author biaoyang
 * date 2019/4/8 000819:21
 */
@Validated
@CrossOrigin
@RestController
@AllArgsConstructor//通过构造注入类实例
public class UserInfoController {

    private final UserInfoRepository userInfoRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

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
        //置空密码,保护敏感信息
        result.setPassword(null);
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

    /**
     * 为登录提示跳转页接口
     *
     * @return
     */
    @GetMapping("/login")
    public ModelAndView login() {
        return new ModelAndView("login");
    }

    @GetMapping("userLogin")
    @ResponseBody
    public JSONObject userLogin(
            @NotBlank(message = "用户密码不能为空")
            @Length(max = 16, min = 4, message = "用户名或密码错误")
            @RequestParam String password,

            @NotBlank(message = "用户名不能为空")
            @Length(max = 10, message = "用户名或密码错误")
            @RequestParam String username) {
        //初始化JSONObject对象
        JSONObject jsonObject = new JSONObject();
        //查询用户名是否存在
        UserInfo userInfo = userInfoRepository.findByUsername(username);
        //判断并校验密码
        if (userInfo != null && bCryptPasswordEncoder.matches(password, userInfo.getPassword())) {
            //封装信息到LoginUser
            LoginUser loginUser = new LoginUser();
            loginUser.setUsername(userInfo.getUsername());
            loginUser.setOrgName("搞笑部");
            loginUser.setJti(JwtUtils.createJti());
            loginUser.setRoles(new HashSet<>(Arrays.asList(userInfo.getRoles())));
            //用户的登录信息正确,为用户生成token,秘钥和gateway-server保持一致
            String accessToken = JwtUtils.createAccessToken(loginUser, 30 * 60 * 1000, JwtDic.BASE64_ENCODE_SECRET);
            String refreshToken = JwtUtils.createRefreshToken(userInfo.getUsername(), 60 * 60 * 1000, JwtDic.BASE64_ENCODE_SECRET);
            //将jwt的唯一标志存储在redis上--->set没有设置某元素过时间时间的功能,据说默认时间是30天,这里省略存储jti
            //封装token
            jsonObject.put("accessToken", accessToken);
            jsonObject.put("refreshToken", refreshToken);
        }
        //返回数据
        return jsonObject;
    }
}
