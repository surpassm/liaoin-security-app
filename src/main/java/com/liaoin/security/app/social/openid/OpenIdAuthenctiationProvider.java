package com.liaoin.security.app.social.openid;

import lombok.Data;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.security.SocialUserDetailsService;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author mc
 * @version 1.0v
 */
@Data
public class OpenIdAuthenctiationProvider implements AuthenticationProvider {

    private SocialUserDetailsService socialUserDetailsService;
    private UsersConnectionRepository usersConnectionRepository;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        OpenIdAuthenctiationToken authenctiationToken = (OpenIdAuthenctiationToken) authentication;
        Set<String> providerUserIds = new HashSet<String>(16);
        providerUserIds.add((String)authenctiationToken.getPrincipal());
        //查询usersConnection 用户是否存在
        Set<String> userIds = usersConnectionRepository.findUserIdsConnectedTo(authenctiationToken.getProviderId(),providerUserIds);
        if (CollectionUtils.isEmpty(userIds) || userIds.size() !=1){
            throw new InternalAuthenticationServiceException("数据表‘usersConnection’用户信息不存在");
        }
        String userId = userIds.iterator().next();
        UserDetails user = socialUserDetailsService.loadUserByUserId(userId);
        if (user == null){
            throw new InternalAuthenticationServiceException("无法获取用户信息");
        }
        OpenIdAuthenctiationToken authenctiationResulrt = new OpenIdAuthenctiationToken(user,user.getAuthorities());
        authenctiationResulrt.setDetails(authenctiationToken);
        return authenctiationResulrt;
    }

    @Override
    public boolean supports(Class<?> authenctiation) {
        return OpenIdAuthenctiationToken.class.isAssignableFrom(authenctiation);
    }
}
