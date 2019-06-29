package io.tomahawkd.pki.controller;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.service.UserLogService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.Map;

@RestController
@RequestMapping("/user/log")
public class UserActivityController {

	@Resource
	private UserLogService userLogService;

	@RequestMapping(value = "/info", method = RequestMethod.POST)
	public String getUserLogById(@RequestBody String body) throws MalformedJsonException {
		try {
			Map<String, String> bodyData =
					new Gson().fromJson(body, new TypeToken<Map<String, String>>() {}.getType());

			return "";
		} catch (JsonSyntaxException e) {
			throw new MalformedJsonException("Malformed Json: " + body);
		} catch (NullPointerException e) {
			throw new MalformedJsonException("Cannot read json value: " + body);
		}
	}
}
