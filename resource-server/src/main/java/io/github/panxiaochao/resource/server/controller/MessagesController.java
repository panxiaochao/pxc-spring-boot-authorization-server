package io.github.panxiaochao.resource.server.controller;

import io.github.panxiaochao.core.response.R;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <p>
 * 消息测试类
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-21
 */
@RestController
@RequestMapping("/messages")
public class MessagesController {

	@GetMapping
	public R<String> getMessages() {
		return R.ok("I'm a message!'");
	}

}
