package io.github.panxiaochao.security.core.endpoint;

import io.github.panxiaochao.core.utils.ArrayUtil;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * <p>
 * 端点工具类.
 * </p>
 *
 * @author Lypxc
 * @since 2022-12-14
 */
public class OAuth2EndpointUtils {

	public static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private OAuth2EndpointUtils() {
	}

	public static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
		Map<String, String[]> parameterMap = request.getParameterMap();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
		parameterMap.forEach((key, values) -> {
			if (ArrayUtil.isNotEmpty(values)) {
				for (String value : values) {
					parameters.add(key, value);
				}
			}
		});
		return parameters;
	}

	public static void throwErrorByParameter(String errorCode, String parameterName, String errorUri) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throw new OAuth2AuthenticationException(error);
	}

	public static void throwError(String errorCode, String description, String errorUri) {
		OAuth2Error error = new OAuth2Error(errorCode, description, errorUri);
		throw new OAuth2AuthenticationException(error);
	}

	public static String transformAuthenticationException(AuthenticationException exception) {
		String msg = "";
		if (exception != null) {
			if (exception instanceof UsernameNotFoundException || exception instanceof BadCredentialsException) {
				msg = "账户不存在或密码错误";
			}
			else if (exception instanceof LockedException) {
				msg = "账户被锁定，请联系管理员!";
			}
			else if (exception instanceof CredentialsExpiredException) {
				msg = "证书过期，请联系管理员!";
			}
			else if (exception instanceof AccountExpiredException) {
				msg = "账户过期，请联系管理员!";
			}
			else if (exception instanceof DisabledException) {
				msg = "账户被禁用，请联系管理员!";
			}
			else if (exception instanceof OAuth2AuthenticationException) {
				OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
				msg = error.getDescription();
			}
		}
		return msg;
	}

}
