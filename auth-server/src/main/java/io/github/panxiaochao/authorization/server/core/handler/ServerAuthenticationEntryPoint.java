package io.github.panxiaochao.authorization.server.core.handler;

import io.github.panxiaochao.core.response.R;
import io.github.panxiaochao.core.utils.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * <p>
 * 无效Token异常类重新，统一返回Json格式.
 * </p>
 *
 * @author Lypxc
 */
public class ServerAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final Logger log = LoggerFactory.getLogger(ServerAuthenticationEntryPoint.class);

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		Throwable cause = authException.getCause();
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setHeader("Content-Type", "application/json;charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.write(JacksonUtil.toString(R.fail(HttpStatus.UNAUTHORIZED.value(), "OAUTH_TOKEN_ILLEGAL", null)));
		out.flush();
		out.close();
	}

}
