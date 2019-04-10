package com.yb.security.oauth.server.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;

/**
 * Description: 用户信息
 * author biaoyang
 * date 2019/4/8 000819:11
 */
@Setter
@Getter
@ToString
@Document
public class UserInfo implements Serializable {
    private static final long serialVersionUID = -955287499319835803L;

    @Id
    private String id;
    //用户名
    private String username;
    //密码
    private String password;
    //角色
    private String[] roles;

}
