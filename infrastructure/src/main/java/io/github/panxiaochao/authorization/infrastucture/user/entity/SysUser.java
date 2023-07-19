package io.github.panxiaochao.authorization.infrastucture.user.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import io.github.panxiaochao.authorization.infrastucture.role.entity.SysRole;
import io.github.panxiaochao.mybatis.plus.po.extend.AutoPO;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

/**
 * <p>
 * 用户表
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
@Getter
@Setter
public class SysUser extends AutoPO {

	private static final long serialVersionUID = 1L;

	/**
	 * 用户真实姓名
	 */
	private String realName;

	/**
	 * 用户昵称（花名）
	 */
	private String nickName;

	/**
	 * 身份证
	 */
	private String idCard;

	/**
	 * 用户头像
	 */
	private String avatar;

	/**
	 * 性别：1男，0女
	 */
	private String sex;

	/**
	 * 地址
	 */
	private String address;

	/**
	 * 邮箱
	 */
	private String email;

	/**
	 * 手机号码
	 */
	private String mobile;

	/**
	 * 电话号码
	 */
	private String tel;

	/**
	 * 传真号码
	 */
	private String fax;

	/**
	 * 排序
	 */
	private Integer sort;

	/**
	 * 备注
	 */
	private String remark;

	/**
	 * 人员状态：1正常，0不正常
	 */
	private String status;

	/**
	 * 皮肤风格
	 */
	private String skins;

	/**
	 * 所在区域或者部门ID，多数据请用逗号隔开
	 */
	private Integer orgId;

	/**
	 * 所在区域或者部门编码code，多数据请用逗号隔开
	 */
	private String orgCode;

	/**
	 * 登陆次数
	 */
	private Integer loginNums;

	/**
	 * 登录失败次数
	 */
	private Integer loginErrorNums;

	/**
	 * 登录时间
	 */
	private LocalDateTime loginTime;

	/**
	 * 帐号超时期限
	 */
	private LocalDateTime expireTime;

	/**
	 * 角色集合
	 */
	@TableField(exist = false)
	private List<SysRole> roles;

	/**
	 * 用户验证类型集合
	 */
	@TableField(exist = false)
	private List<SysUserAuths> sysUserAuths;

}
