package io.github.panxiaochao.authorization.server.core.handler;

import io.github.panxiaochao.authorization.server.core.constants.GlobalSecurityConstant;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>
 * 登录表单成功处理类, 做一些日志处理.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-18
 */
public class ServerFormAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private RequestCache requestCache = new HttpSessionRequestCache();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws ServletException, IOException {
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (savedRequest == null) {
			// super.onAuthenticationSuccess(request, response, authentication);
			// return;
			getRedirectStrategy().sendRedirect(request, response, GlobalSecurityConstant.LOGIN_PATH + "?error");
			return;
		}
		String targetUrlParameter = getTargetUrlParameter();
		if (isAlwaysUseDefaultTargetUrl()
				|| (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
			this.requestCache.removeRequest(request, response);
			// TODO 优化点
			// super.onAuthenticationSuccess(request, response, authentication);
			getRedirectStrategy().sendRedirect(request, response, GlobalSecurityConstant.LOGIN_PATH + "?error");
			return;
		}
		clearAuthenticationAttributes(request);
		// Use the DefaultSavedRequest URL
		String targetUrl = savedRequest.getRedirectUrl();
		getRedirectStrategy().sendRedirect(request, response, targetUrl);
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}

}
