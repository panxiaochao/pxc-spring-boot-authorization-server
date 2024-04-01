package io.github.panxiaochao.authorization.server.core.authorization.oidc;

import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetail;
import io.github.panxiaochao.security.core.endpoint.OAuth2EndpointUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

/**
 * <p>
 * OIDC 1.0 UserInfo and then converts it to an
 * {@link OidcUserDetailAuthenticationConverter} used for authenticating the authorization
 * grant.
 * </p>
 *
 * @author Lypxc
 * @since 2024-03-27
 * @version 1.0
 */
public class OidcUserDetailAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
		OidcUserDetail.Builder builder = OidcUserDetail.builder();
		builder.address("浙江杭州")
			.birthdate("1990-01-01")
			.email("545685602@qq.com")
			.emailVerified(true)
			.familyName("潘")
			.givenName("骁超")
			.gender("male")
			.name("潘骁超")
			.nickname("Lypxc")
			.phoneNumber("15381100508")
			.phoneNumberVerified("true")
			.middleName("骁")
			.updatedAt("2015-01-01")
			.roles(Arrays.asList("admin", "guest"))
			.username("admin");

		return new OidcUserDetailAuthenticationToken(authentication, builder.build());
	}

}
