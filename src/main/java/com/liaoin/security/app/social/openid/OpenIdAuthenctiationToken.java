package com.liaoin.security.app.social.openid;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import javax.security.auth.Subject;
import java.util.Collection;

/**
 * @author mc
 * @version 1.0v
 */
@Getter
@Setter
public class OpenIdAuthenctiationToken extends AbstractAuthenticationToken {
    private static final long servialVsersion = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object principal;
    //服务提供商
    private String providerId;

    /**
     * @param openId 应用标识
     * @param providerId 服务提供商
	 *
     */
    public OpenIdAuthenctiationToken( String openId, String providerId) {
        super(null);
        this.principal = openId;
        this.providerId = providerId;
        setAuthenticated(false);
    }

    public OpenIdAuthenctiationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }
}
