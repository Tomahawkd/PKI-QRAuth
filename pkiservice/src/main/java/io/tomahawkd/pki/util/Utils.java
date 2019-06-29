package io.tomahawkd.pki.util;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.exceptions.ParamNotFoundException;

import java.util.Map;

public class Utils {

	public static Map<String, String> wrapMapFromJson(String json) throws MalformedJsonException {

		try {
			return new Gson().fromJson(json, new TypeToken<Map<String, String>>() {
			}.getType());
		} catch (JsonSyntaxException e) {
			throw new MalformedJsonException("Malformed Json: " + json);
		} catch (NullPointerException e) {
			throw new MalformedJsonException("Cannot read json value: " + json);
		}
	}

	public static Map<String, String> wrapMapFromJson(String json, String[] params)
			throws ParamNotFoundException, MalformedJsonException {

		Map<String, String> map = wrapMapFromJson(json);

		for (String param : params) {
			if (!map.containsKey(param)) throw new ParamNotFoundException("Json key not exist: " + json);
		}

		return map;
	}
}
