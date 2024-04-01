package io.github.panxiaochao.authorization.server.endpoint;

import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetailScopes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * <p>
 * 自定义同意授权处理类
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-19
 */
@Controller
@RequestMapping
public class AuthorizationConsentController {

	private final RegisteredClientRepository registeredClientRepository;

	private final OAuth2AuthorizationConsentService authorizationConsentService;

	public AuthorizationConsentController(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationConsentService authorizationConsentService) {
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationConsentService = authorizationConsentService;
	}

	@GetMapping(value = "/oauth2/consent")
	public String consent(Principal principal, Model model,
			@RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
			@RequestParam(OAuth2ParameterNames.SCOPE) String scope,
			@RequestParam(OAuth2ParameterNames.STATE) String state) {

		// 要批准的范围和以前批准的范围
		Set<String> scopesToApprove = new HashSet<>();
		Set<String> previouslyApprovedScopes = new HashSet<>();
		// 查询 clientId 是否存在
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		// 查询当前的授权许可
		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService
			.findById(registeredClient.getId(), principal.getName());
		// 已授权范围
		Set<String> authorizedScopes;
		if (currentAuthorizationConsent != null) {
			authorizedScopes = currentAuthorizationConsent.getScopes();
		}
		else {
			authorizedScopes = Collections.emptySet();
		}
		for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
			// if (OidcUserDetailScopes.OPENID.equals(requestedScope)) {
			// continue;
			// }
			// 如果已授权范围包含了请求范围，则添加到以前批准的范围的 Set, 否则添加到要批准的范围
			if (authorizedScopes.contains(requestedScope)) {
				previouslyApprovedScopes.add(requestedScope);
			}
			else {
				scopesToApprove.add(requestedScope);
			}
		}

		model.addAttribute("clientId", clientId);
		model.addAttribute("state", state);
		model.addAttribute("scopes", withDescription(scopesToApprove));
		model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
		model.addAttribute("principalName", principal.getName());

		return "html/consent";
	}

	private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
		return scopes.stream().map(ScopeWithDescription::new).collect(Collectors.toSet());
	}

	public static class ScopeWithDescription {

		private static final String DEFAULT_DESCRIPTION = "未知范围 - 我们无法提供有关此权限的信息, 请在授予此权限时谨慎";

		private static final Map<String, String> SCOPE_DESCRIPTIONS = new HashMap<>();
		static {
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.PHONE, "此应用程序将能够读取您的手机号码信息");
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.PROFILE, "此应用程序将能够读取您的个人资料信息");
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.OPENID, "此应用程序将能够读取您的openid信息");
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.ADDRESS, "此应用程序将能够读取您的地址信息");
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.EMAIL, "此应用程序将能够读取您的邮箱信息");
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.USERNAME, "此应用程序将能够读取您的用户账号信息");
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.ROLES, "此应用程序将能够读取您的用户角色信息");
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.UNION_ID, "此应用程序将能够读取您的联合ID信息");
			SCOPE_DESCRIPTIONS.put(OidcUserDetailScopes.TENANT_ID, "此应用程序将能够读取您的租户ID信息");
			SCOPE_DESCRIPTIONS.put("message.read", "此应用程序将能够读取您的信息");
			SCOPE_DESCRIPTIONS.put("message.write", "此应用程序将能够添加新信息, 它还可以编辑和删除现有信息");
			SCOPE_DESCRIPTIONS.put("other.scope", "这是范围描述的另一个范围示例");
		}

		public final String scope;

		public final String description;

		ScopeWithDescription(String scope) {
			this.scope = scope;
			this.description = SCOPE_DESCRIPTIONS.getOrDefault(scope, DEFAULT_DESCRIPTION);
		}

	}

}
