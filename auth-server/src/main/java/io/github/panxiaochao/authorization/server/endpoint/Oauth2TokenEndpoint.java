package io.github.panxiaochao.authorization.server.endpoint;

import io.github.panxiaochao.core.response.R;
import io.github.panxiaochao.core.utils.StrUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

/**
 * <p>
 * 自定义端点登录类
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-19
 */
@Controller
@RequiredArgsConstructor
@RequestMapping
public class Oauth2TokenEndpoint {

	private final OAuth2AuthorizationService authorizationService;

	/**
	 * 跳转自定义认证页面
	 */
	@GetMapping("/token/login")
	public String login() {
		return "html/login";
	}

	/**
	 * 错误页面
	 */
	@GetMapping("/error")
	public String error() {
		return "html/error";
	}

	/**
	 * 退出并删除token
	 * @param authHeader Authorization
	 */
	@DeleteMapping("/token/logout")
	@ResponseBody
	public R<Boolean> logout(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {
		if (StrUtil.isBlank(authHeader)) {
			return R.ok();
		}
		String tokenValue = authHeader.replace(OAuth2AccessToken.TokenType.BEARER.getValue(), StrUtil.EMPTY).trim();
		return removeToken(tokenValue);
	}

	/**
	 * 令牌管理调用
	 * @param token token
	 */
	@DeleteMapping("/token/{token}")
	@ResponseBody
	public R<Boolean> removeToken(@PathVariable("token") String token) {
		OAuth2Authorization authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
		if (authorization != null) {
			// 清空access token
			authorizationService.remove(authorization);
		}
		return R.ok();
	}

}
