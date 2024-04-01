package io.github.panxiaochao.authorization.server.core.authorization.oidc;

import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetail;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>
 * OIDC 登录成功处理类, 做一些日志处理.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-18
 */
public class OidcUserDetailAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final HttpMessageConverter<OidcUserDetail> userInfoHttpMessageConverter = new OidcUserDetailHttpMessageConverter();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		OidcUserDetailAuthenticationToken userInfoAuthenticationToken = (OidcUserDetailAuthenticationToken) authentication;
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.userInfoHttpMessageConverter.write(userInfoAuthenticationToken.getUserInfo(), null, httpResponse);
	}

}
