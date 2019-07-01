package io.tomahawkd.pki;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class KeyDistributionTest {

	@Autowired
	private TestRestTemplate testRestTemplate;

	@Test
	public void authenticateServerKey() throws IOException {

		String auth = this.testRestTemplate.getForObject("/keys/auth", String.class);
		String data = new String(Files.readAllBytes(Paths.get("./src/main/resources/auth.pub")));
		assertThat(auth).isEqualTo(data);
	}

	@Test
	public void serverKey() {
		String server = this.testRestTemplate.postForObject("/keys/server", "123", String.class);
		System.out.println(server);
	}
}
