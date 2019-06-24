package io.tomahawkd.pki.controller;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.service.UserKeyService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SystemApiController {

	@Resource
	private UserKeyService userKeyService;

	@RequestMapping(value = "/info", method = RequestMethod.POST)
	public String generateKeysForUser(@RequestBody String body) throws MalformedJsonException,
			CipherErrorException {
		try {
			Map<String, Integer> bodyData =
					new Gson().fromJson(body, new TypeToken<Map<String, Integer>>() {
					}.getType());

			return "";
		} catch (JsonSyntaxException e) {
			throw new MalformedJsonException("Malformed Json: " + body);
		} catch (NullPointerException e) {
			throw new MalformedJsonException("Cannot read json value: " + body);
		}
	}
}
