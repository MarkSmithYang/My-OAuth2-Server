package com.yb.security.oauth.server.model;

import com.sun.javafx.scene.paint.GradientUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;

/**
 * Description: 用户信息
 * author biaoyang
 * date 2019/4/8 000819:11
 */
@Setter
@Getter
@ToString
@Document
public class UserInfo implements UserDetails,Serializable {
    private static final long serialVersionUID = -955287499319835803L;

    @Id
    private String id;
    //用户名
    private String username;
    //密码
    private String password;
    //角色
    private String[] roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return AuthorityUtils.createAuthorityList(this.roles);
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
