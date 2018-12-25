package com.liaoin.security.app.social.openid;

import com.liaoin.security.core.constants.SecurityConstants;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author mc
 * @version 1.0v
 */

public class OpenIdAuthenctiationFilter extends AbstractAuthenticationProcessingFilter {
    private String openIdparameter = SecurityConstants.DEFAULT_PARAMETER_NAME_OPENID;
    private String providerIdParameter = SecurityConstants.DEFAULT_PARAMETER_NAME_PROVIDERID;
    private boolean postOnly = true;
    protected OpenIdAuthenctiationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }


    protected OpenIdAuthenctiationFilter() {
        super(new AntPathRequestMatcher(SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_OPENID,"POST"));
    }
    protected OpenIdAuthenctiationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (postOnly && !request.getMethod().equals("POST")){
            throw new AuthenticationServiceException("Authentication method not supported"+request.getMethod());
        }
        String openId = obtainOpenId(request);
        String providerId = abtainproviderId(request);
        if (openId == null) {
            openId = "";
        }
        if (providerId == null){
            providerId="";
        }
        openId = openId.trim();
        providerId = providerId.trim();
        OpenIdAuthenctiationToken authenctiationToken = new OpenIdAuthenctiationToken(openId,providerId);
        setDetails(request,authenctiationToken);
        return this.getAuthenticationManager().authenticate(authenctiationToken);
    }

    private void setDetails(HttpServletRequest request, OpenIdAuthenctiationToken authenctiationToken) {
        authenctiationToken.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    /**
     * 获取providerId
     * @param request
     * @return
     */
    private String abtainproviderId(HttpServletRequest request) {
        return request.getParameter(providerIdParameter);
    }

    /**
     * 获取OpenId
     * @param request
     * @return
     */
    private String obtainOpenId(HttpServletRequest request) {
        return request.getParameter(openIdparameter);
    }
}
