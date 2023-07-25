package io.github.panxiaochao.security.core.handler;

import io.github.panxiaochao.core.response.R;
import io.github.panxiaochao.core.utils.JacksonUtil;
import io.github.panxiaochao.security.core.endpoint.OAuth2EndpointUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

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

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		String msg = OAuth2EndpointUtils.transformAuthenticationException(authException);
		String errorMessage = StringUtils.hasText(msg) ? "OAUTH_TOKEN_UNAUTHORIZED: [" + msg + "]"
				: "OAUTH_TOKEN_UNAUTHORIZED";
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setHeader("Content-Type", "application/json;charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.write(JacksonUtil.toString(R.fail(HttpStatus.UNAUTHORIZED.value(), errorMessage, null)));
		out.flush();
		out.close();
	}

}
