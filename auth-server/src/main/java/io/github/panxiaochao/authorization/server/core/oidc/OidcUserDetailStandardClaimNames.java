package io.github.panxiaochao.authorization.server.core.oidc;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

/**
 * <p>
 * OpenID Connect Core 1.0规范定义的“标准声明”的名称，可以在UserInfo响应或ID令牌中返回。
 * <h2>OIDC 用户信息字段含义</h2>
 * <table>
 * <thead>
 * <tr>
 * <th>字段名</th>
 * <th>翻译</th>
 * </tr>
 * </thead> <tbody>
 * <tr>
 * <td>sub</td>
 * <td>subject 的缩写，唯一标识，一般为用户 ID</td>
 * </tr>
 * <tr>
 * <td>name</td>
 * <td>姓名</td>
 * </tr>
 * <tr>
 * <td>given_name</td>
 * <td>名字</td>
 * </tr>
 * <tr>
 * <td>family_name</td>
 * <td>姓氏</td>
 * </tr>
 * <tr>
 * <td>middle_name</td>
 * <td>中间名</td>
 * </tr>
 * <tr>
 * <td>nickname</td>
 * <td>昵称</td>
 * </tr>
 * <tr>
 * <td>preferred_username</td>
 * <td>希望被称呼的名字</td>
 * </tr>
 * <tr>
 * <td>profile</td>
 * <td>基础资料</td>
 * </tr>
 * <tr>
 * <td>picture</td>
 * <td>头像</td>
 * </tr>
 * <tr>
 * <td>website</td>
 * <td>网站链接</td>
 * </tr>
 * <tr>
 * <td>email</td>
 * <td>电子邮箱</td>
 * </tr>
 * <tr>
 * <td>email_verified</td>
 * <td>邮箱是否被认证</td>
 * </tr>
 * <tr>
 * <td>gender</td>
 * <td>性别</td>
 * </tr>
 * <tr>
 * <td>birthdate</td>
 * <td>生日</td>
 * </tr>
 * <tr>
 * <td>zoneinfo</td>
 * <td>时区</td>
 * </tr>
 * <tr>
 * <td>locale</td>
 * <td>区域</td>
 * </tr>
 * <tr>
 * <td>phone_number</td>
 * <td>手机号</td>
 * </tr>
 * <tr>
 * <td>phone_number_verified</td>
 * <td>认证手机号</td>
 * </tr>
 * <tr>
 * <td>address</td>
 * <td>地址</td>
 * </tr>
 * <tr>
 * <td>updated_at</td>
 * <td>信息更新时间</td>
 * </tr>
 * <td>username</td>
 * <td>用户账号</td>
 * </tr>
 * <td>roles</td>
 * <td>用户角色数组</td>
 * </tr>
 * <td>union_id</td>
 * <td>联合ID</td>
 * </tr>
 * <td>tenant_id</td>
 * <td>租户ID</td>
 * </tr>
 * </tbody>
 * </table>
 * <h2>scope 参数对应的用户信息</h2>
 * <table>
 * <thead>
 * <tr>
 * <th>scope名</th>
 * <th>对应信息</th>
 * </tr>
 * </thead>
 * <tbody>
 * <tr>
 * <td>username</td>
 * <td>username</td>
 * </tr>
 * <tr>
 * <td>address</td>
 * <td>address</td>
 * </tr>
 * <tr>
 * <td>email</td>
 * <td>email，email_verified</td>
 * </tr>
 * <tr>
 * <td>phone</td>
 * <td>phone_number, phone_number_verified</td>
 * </tr>
 * <tr>
 * <td>profile</td>
 * <td>birthdate，family_name，gender，given_name，<br/>locale，middle_name，name，nickname，<br/>picture，preferred_username，profile，<br/>updated_at，website，zoneinfo</td>
 * </tr>
 * <tr>
 * <td>roles</td>
 * <td>对应 role 信息，用户的角色列表</td>
 * </tr>
 * <tr>
 * <td>union_id</td>
 * <td>用户的 unionid 字段</td>
 * </tr>
 * <tr>
 * <td>tenant_id</td>
 * <td>用户的 tenant_id 字段</td>
 * </tr>
 * </tbody>
 * </table>
 * </p>
 *
 * @author Lypxc
 * @since 2024-03-28
 * @version 1.0
 */
public interface OidcUserDetailStandardClaimNames extends StandardClaimNames {

	/**
	 * {@code username} - the user's username
	 */
	String USERNAME = "username";

	/**
	 * {@code roles} - the user's roles arrays
	 */
	String ROLES = "roles";

	/**
	 * {@code union_id} - the user's union_id
	 */
	String UNION_ID = "union_id";

	/**
	 * {@code tenant_id} - the user's tenant_id
	 */
	String TENANT_ID = "tenant_id";

}
