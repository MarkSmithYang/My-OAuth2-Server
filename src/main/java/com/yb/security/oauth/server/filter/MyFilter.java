package com.yb.security.oauth.server.filter;

import com.yb.security.oauth.server.dic.JwtDic;
import com.yb.security.oauth.server.model.LoginUser;
import com.yb.security.oauth.server.utils.JwtUtils;
import com.yb.security.oauth.server.utils.LoginUserUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Description: 用于认证过token合法性的校验
 * author biaoyang
 * date 2019/5/6 000615:56
 */
@Component
public class MyFilter extends SecurityContextPersistenceFilter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        //获取请求头里的token信息
        String header = request.getHeader(JwtDic.HEADERS_NAME);
        //判断token是否存在,并校验其合法性,(checkAndGetPayload已经做了判空和前缀判断)
        LoginUser loginUser = JwtUtils.checkAndGetPayload(header, JwtDic.BASE64_ENCODE_SECRET);
        //判断是否能正确解析出放在荷载里的用户信息(验证签名不通过返回null)
        if (Objects.nonNull(loginUser)) {
            //实例化一个装权限/角色的集合
            Set<GrantedAuthority> roles = new HashSet<>(5);
            //判断用户是否带有权限/角色信息
            if (!CollectionUtils.isEmpty(loginUser.getRoles())) {
                //注意这里需要为角色添加前缀,接口认证的时候是带有前缀的,否则匹配不上
                loginUser.getRoles().forEach(s -> roles.add(new SimpleGrantedAuthority(JwtDic.SECURITY_ROLE_PREFIX + s)));
            }
            //设置安全上下文信息
            Authentication authentication = new UsernamePasswordAuthenticationToken(loginUser.getUsername(), "", roles);
            //设置安全信息到上下文中
            SecurityContextHolder.getContext().setAuthentication(authentication);
            //设置用户信息到LoginUserUtils里方便获取用户信息
            LoginUserUtils.setUser(loginUser);
        }
        //过滤请求
        chain.doFilter(req, res);
    }
}
