package io.github.panxiaochao.resource.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.net.InetAddress;

/**
 * <p>
 * 启动器
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@SpringBootApplication
public class ResourceServerApplication {

	private static final Logger LOG = LoggerFactory.getLogger(ResourceServerApplication.class);

	/**
	 * @param args args
	 * @throws Exception Exception
	 */
	public static void main(String[] args) throws Exception {
		ConfigurableApplicationContext application = SpringApplication.run(ResourceServerApplication.class, args);
		Environment env = application.getEnvironment();
		String ip = InetAddress.getLocalHost().getHostAddress();
		String applicationName = env.getProperty("spring.application.name") + " is running! Access URLs:";
		String port = env.getProperty("server.port");
		String path = env.getProperty("server.servlet.context-path");
		if (!StringUtils.hasText(path)) {
			path = "";
		}
		LOG.info("\n----------------------------------------------------------\n\t{}{}{}{}", applicationName,
				"\n\tLocal    访问网址: \thttp://localhost:" + port + path,
				"\n\tExternal 访问网址: \thttp://" + ip + ":" + port + path,
				"\n----------------------------------------------------------\n");
	}

}
