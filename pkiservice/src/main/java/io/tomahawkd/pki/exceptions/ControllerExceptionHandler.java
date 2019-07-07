package io.tomahawkd.pki.exceptions;

import io.tomahawkd.pki.util.Message;
import io.tomahawkd.pki.util.ThreadContext;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class ControllerExceptionHandler {

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Malformed Json")
	@ExceptionHandler(MalformedJsonException.class)
	@ResponseBody
	public Map<String, Object> malformedJson(Exception e) {
		return handle(e);
	}

	@ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "Not found")
	@ExceptionHandler({NullPointerException.class, NotFoundException.class})
	public Map<String, Object> notFound(Exception e) {
		return handle(e);

	}

	@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR, reason = "Cipher error")
	@ExceptionHandler(CipherErrorException.class)
	public Map<String, Object> cipherIssue(Exception e) {
		return handle(e);

	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Malformed Base64 value")
	@ExceptionHandler(Base64EncodeException.class)
	public Map<String, Object> base64Issue(Exception e) {
		return handle(e);

	}

	@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR, reason = "Other error")
	@ExceptionHandler(Exception.class)
	public Map<String, Object> others(Exception e) {
		e.printStackTrace();
		return handle(e);
	}

	private Map<String, Object> handle(Exception e) {
		String tResponse = ThreadContext.getContext().get();
		Message<String> message = new Message<String>().setError().setMessage(e.getMessage());
		Map<String, Object> response = new HashMap<>();
		if (tResponse != null && !tResponse.isEmpty()) response.put("T", tResponse);
		response.put("M", message);
		return response;
	}
}
