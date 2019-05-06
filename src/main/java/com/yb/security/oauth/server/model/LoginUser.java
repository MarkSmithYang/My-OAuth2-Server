package com.yb.security.oauth.server.model;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

/**
 * Description: 登录用户信息封装类
 * author biaoyang
 * date 2019/4/25 002511:10
 */
@Getter
@Setter
public class LoginUser {

    /**
     * 用户id
     */
    private String userId;

    /**
     * 用户名
     */
    @JSONField(name = "sub")
    private String username;

    /**
     * 用户姓名
     */
    private String fullName;

    /**
     * 用户身份证号
     */
    private String idCard;

    /**
     * 手机号
     */
    private String cellphone;

    /**
     * 机构代码
     */
    private Long orgCode;

    /**
     * 机构名称(部门)
     */
    private String orgName;

    /**
     * 角色
     */
    private Set<String> roles;

    /**
     * 权限
     */
    private Set<String> perms;

    /**
     * 用户ip
     */
    private String ip;

    /**
     * 用户请求uri
     */
    private String uri;

    /**
     * 登录终端
     */
    private String from;

    /**
     * jti 唯一代码
     */
    private String jti;

    /**
     * 认证状态：未认证,认证中,通过,不通过auth_status
     */
    private String authStatus;
}
