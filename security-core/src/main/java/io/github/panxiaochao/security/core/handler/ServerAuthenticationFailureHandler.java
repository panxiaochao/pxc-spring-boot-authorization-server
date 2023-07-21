package io.github.panxiaochao.security.core.handler;

import io.github.panxiaochao.core.response.R;
import io.github.panxiaochao.core.utils.JacksonUtil;
import io.github.panxiaochao.security.core.endpoint.OAuth2EndpointUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * <p>
 * 登录失败.
 * </p>
 *
 * @author Lypxc
 */
public class ServerAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final Logger log = LoggerFactory.getLogger(ServerAuthenticationFailureHandler.class);

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) {
		String msg = OAuth2EndpointUtils.transformAuthenticationException(exception);
		String username = request.getParameter(OAuth2ParameterNames.USERNAME);
		log.error("{}登录失败，异常：", username, exception);
		response.setStatus(HttpStatus.OK.value());
		response.setHeader("Content-Type", "application/json;charset=UTF-8");
		try {
			PrintWriter out = response.getWriter();
			out.write(JacksonUtil.toString(R.fail(HttpServletResponse.SC_FORBIDDEN, msg, null)));
			out.flush();
			out.close();
		}
		catch (Exception e) {
			log.error("返回错误信息失败", e);
		}
	}

}
