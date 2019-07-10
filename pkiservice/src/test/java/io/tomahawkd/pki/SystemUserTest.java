package io.tomahawkd.pki;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class SystemUserTest {

	@Autowired
	private TestRestTemplate testRestTemplate;


	@Test
	public void register() throws IOException {

		String body = "{\"user\": \"123\", \"pass\": \"123\"}";
		String auth = this.testRestTemplate.postForObject("/manage/register", body, String.class);
		assertThat(auth).isEqualTo("success");
	}

	@Test
	public void registerSystem() {
		String body = "{\"user\": \"123\", \"pass\": \"123\"}";
		String regsys = this.testRestTemplate.postForObject("/manage/sysreg", body, String.class);
		System.out.println(regsys);
		assertThat(regsys).isEqualTo("success");
	}

	@Test
	public void listSystemAndKey() {

		String body = "{\"user\": \"123\", \"pass\": \"123\"}";
		String getlist = this.testRestTemplate.postForObject("/manage/systems", body, String.class);
		assertThat(getlist).startsWith("[").endsWith("]");
		System.out.println(getlist);

		List<Map<String, String>> list = new Gson().fromJson(getlist, new TypeToken<List<Map<String, String>>>() {
		}.getType());
		String api = list.get(0).get("api");
		assertThat(api).isNotNull();

		String body2 = "{\"user\": \"123\", \"pass\": \"123\", \"system\": \"" + api + "\"}";
		String get = this.testRestTemplate.postForObject("/manage/key", body2, String.class);
		System.out.println(get);
		assertThat(get).contains("\n");
	}

}
