package com.liaoin.security.app.controller;

import com.liaoin.security.app.social.AppSingUpUtils;
import com.liaoin.security.core.support.SocialUserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.web.ProviderSignInUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;

/**
 * @author mc
 * @version 1.0v
 * 用于处理/social/signUp，
 */
@RestController
public class AppSecurityController {

    @Autowired
    private ProviderSignInUtils providerSignInUtils;

    @Autowired
    private AppSingUpUtils appSingUpUtils;

    /**
     * 绑定三方登陆账号，如果没有账户信息，用该接口实现用户新增绑定三方账号
     * @param request
     * @return
     */
    @GetMapping("/social/signUp")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public SocialUserInfo getSocialUserInfo(HttpServletRequest request) {
        Connection<?> connection = providerSignInUtils.getConnectionFromSession(new ServletWebRequest(request));
        //从session里面转存
        appSingUpUtils.saveConnectionData(new ServletWebRequest(request),connection.createData());

        return SocialUserInfo.builder()
                .providerId(connection.getKey().getProviderId())
                .headimg(connection.getImageUrl())
                .nickname(connection.getDisplayName())
                .providerUserId(connection.getKey().getProviderUserId())
                .build();
    }
}
