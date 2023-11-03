package io.github.panxiaochao.authorization;

import org.mybatis.spring.annotation.MapperScan;
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
@MapperScan("io.github.panxiaochao.authorization.infrastucture.**.mapper")
public class ServerApplication {

	private static final Logger LOG = LoggerFactory.getLogger(ServerApplication.class);

	/**
	 * @param args args
	 * @throws Exception Exception
	 */
	public static void main(String[] args) throws Exception {
		ConfigurableApplicationContext application = SpringApplication.run(ServerApplication.class, args);
		Environment env = application.getEnvironment();
		String ip = InetAddress.getLocalHost().getHostAddress();
		String applicationName = env.getProperty("spring.application.name") + " is running! Access URLs:";
		String port = env.getProperty("server.port");
		String path = env.getProperty("server.servlet.context-path");
		if (!StringUtils.hasText(path) || "/".equals(path)) {
			path = "";
		}
		LOG.info("\n----------------------------------------------------------\n\t{}{}{}{}", applicationName,
				"\n\tLocal    访问网址: \thttp://localhost:" + port + path,
				"\n\tExternal 访问网址: \thttp://" + ip + ":" + port + path,
				"\n----------------------------------------------------------\n");
	}

}
