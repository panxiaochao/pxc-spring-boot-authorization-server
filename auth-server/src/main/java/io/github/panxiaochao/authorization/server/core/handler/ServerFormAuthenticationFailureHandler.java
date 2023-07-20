package io.github.panxiaochao.authorization.server.core.handler;

import io.github.panxiaochao.authorization.server.core.constants.GlobalSecurityConstant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>
 * From登录失败.
 * </p>
 *
 * @author Lypxc
 */
public class ServerFormAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final Logger log = LoggerFactory.getLogger(ServerFormAuthenticationFailureHandler.class);

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) {
		try {
			log.error(exception.getMessage());
			// String url = String.format("/login?error=%s",
			// URLEncoder.encode(exception.getMessage(), StandardCharsets.UTF_8.name()));
			response.sendRedirect(GlobalSecurityConstant.LOGIN_PATH + "?error");
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
