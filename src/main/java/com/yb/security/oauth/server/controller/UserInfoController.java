package com.yb.security.oauth.server.controller;

import com.alibaba.fastjson.JSONObject;
import com.yb.security.oauth.server.dic.ApplicationConfig;
import com.yb.security.oauth.server.dic.JwtDic;
import com.yb.security.oauth.server.model.LoginUser;
import com.yb.security.oauth.server.model.UserInfo;
import com.yb.security.oauth.server.repository.UserInfoRepository;
import com.yb.security.oauth.server.utils.GetIpAddressUtils;
import com.yb.security.oauth.server.utils.JwtUtils;
import com.yb.security.oauth.server.utils.LoginUserUtils;
import lombok.AllArgsConstructor;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.hibernate.validator.constraints.Length;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotBlank;
import java.io.Serializable;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

/**
 * //这个是直接跳转视图,仅需一个名称为index的html文件
 * return new ModelAndView("index");
 * //这个是通过请求转发到指定的接口来实现跳转的,这个不仅需要一个名为login的html文件,
 * //还需要一个url为login的接口来跳转到login视图,很显然,直接跳视图即可,不用再去接口跳了,太麻烦
 * 注意login这个接口是必要的,实测缺少接口方法,资源服务器那里的跳转不会成功的,从需要放开跳转的路径就知道是接口而不是直接跳转视图了
 * return new ModelAndView("forward:/login");
 * Description:
 * author biaoyang
 * date 2019/4/8 000819:21
 */
@Validated
@CrossOrigin
@RestController
@AllArgsConstructor//通过构造注入类实例
public class UserInfoController {

    private final RestTemplate restTemplate;
    private final ApplicationConfig applicationConfig;
    private final UserInfoRepository userInfoRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final RedisTemplate<String, Serializable> redisTemplate;

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
        userInfoA.setUsername("jack");
        //为密码加密
        userInfoA.setPassword(bCryptPasswordEncoder.encode("jack"));
        userInfoA.setRoles(new String[]{"ROLE_ADMIN", "ROLE_USER"});
        userInfoRepository.save(userInfoA);
    }

    /**
     * 根据用户名获取用户信息
     *
     * @param username
     * @return
     */
    @PreAuthorize("hasRole('ADMIN')")//已验证合法性后可访问--------------这个是不能设置的,因为认证服务器发的token是没有这个信息的
    @GetMapping("findByUsername")
    public UserInfo findByUsername(
            @NotBlank(message = "用户名不能为空")
            @Length(max = 20, message = "用户名有误")
            @RequestParam String username) {
        Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
        if ( authentication1 instanceof OAuth2Authentication) {
            OAuth2Authentication authentication = (OAuth2Authentication) authentication1;
            Object principal = authentication.getPrincipal();
            System.err.println(principal.toString());
        }
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

    @GetMapping("/token")
    public JSONObject token(HttpServletRequest request) {
        SecurityContextHolder.getContext().setAuthentication(null);
        //获取认证服务器发的授权码code
        String code = request.getParameter("code");
        //请求认证服务器的token的url
        String url = applicationConfig.getAuthUrl() + "/oauth/token?grant_type=" + applicationConfig.getGrantType() + "&client_id=" + applicationConfig.getClientId() +
                "&client_secret=" + applicationConfig.getClientSecret() + "&redirect_uri=" + applicationConfig.getRedirectUrl() + "&code={code}";
        //其实这个就应该是服务器内部的查询,因为还有客户端申请的client_secret秘钥等信息,可以很好的避免暴露带来的安全问题
        JSONObject forObject = restTemplate.getForObject(url, JSONObject.class, code);//已经从配置把post请求改为get
        //返回认证服务器发的token信息
        return forObject;
    }

    @GetMapping("/loginAuthorize")
    public ModelAndView loginAuthorize(
            @NotBlank(message = "用户密码不能为空")
            @Length(max = 16, min = 4, message = "用户名或密码错误")
            @RequestParam String password,

            @NotBlank(message = "用户名不能为空")
            @Length(max = 10, message = "用户名或密码错误")
            @RequestParam String username, HttpServletRequest request) {
        //查询用户名是否存在
        UserInfo userInfo = userInfoRepository.findByUsername(username);
        //判断并校验密码
        if (userInfo != null && bCryptPasswordEncoder.matches(password, userInfo.getPassword())) {
            //封装用户信息去生成token
            LoginUser loginUser = new LoginUser();
            loginUser.setUsername(userInfo.getUsername());
            loginUser.setRoles(new HashSet<>(Arrays.asList(userInfo.getRoles())));
            //把用户信息设置到LoginUserUtils
            LoginUserUtils.setUser(loginUser);
            //生成用户登录的token信息
            String accessToken = JwtUtils.createAccessToken(loginUser, 30 * 60 * 1000, JwtDic.BASE64_ENCODE_SECRET);
            //获取登录用户的ip地址,用来作为key,因为redis存储,用来区分不同用户,统一台电脑登录的用户只会是最后登录的用户的登录信息(因为key相同,会被覆盖)
            String ipAddress = StringUtils.isNotBlank(GetIpAddressUtils.getIpAddress(request)) ? GetIpAddressUtils.getIpAddress(request) : "";
            //把token信息存储到redis里去,以便过滤器处理token认证(主要是解决没有前端设置token到请求头/请求参数)
            redisTemplate.opsForValue().set(JwtDic.ACCESS_TOKEN + ipAddress, accessToken, 30, TimeUnit.MINUTES);
            //设置模型和视图
            ModelAndView view = new ModelAndView("index");
            //请求授权码的url
            String url = applicationConfig.getAuthUrl() + "/oauth/authorize?response_type=" + applicationConfig.getResponseType() +
                    "&client_id=" + applicationConfig.getClientId() + "&redirect_uri=" + applicationConfig.getRedirectUrl();
            //这里可以灵活的拼接url,再传递到html去
            view.getModel().put("authUrl", url);
            //返回模型和视图
            return view;
        }
        //设置登录失败提示
        ModelAndView view = new ModelAndView("login");
        view.getModel().put("fail", "用户名或密码错误");
        //返回数据
        return view;
    }


    //&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&

    /**
     * 用来认证security的登录接口-----注意这个只能认证security,
     * 而这里根本用不着这个,因为访问这里的资源,需要认证服务器颁发的token,而不是这个接口给的token
     *
     * @param password
     * @param username
     * @return
     */
    @GetMapping("/userLogin")
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
            loginUser.setOrgName("搞笑部");
            loginUser.setJti(JwtUtils.createJti());
            loginUser.setUsername(userInfo.getUsername());
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
