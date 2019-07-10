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

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(MalformedJsonException.class)
	@ResponseBody
	public Map<String, String> malformedJson(Exception e) {
		return handle(e);
	}

	@ResponseStatus(HttpStatus.NOT_FOUND)
	@ExceptionHandler({NullPointerException.class, NotFoundException.class})
	@ResponseBody
	public Map<String, String> notFound(Exception e) {
		return handle(e);

	}

	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	@ExceptionHandler(CipherErrorException.class)
	@ResponseBody
	public Map<String, String> cipherIssue(Exception e) {
		return handle(e);

	}

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(Base64EncodeException.class)
	@ResponseBody
	public Map<String, String> base64Issue(Exception e) {
		return handle(e);

	}

	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	@ExceptionHandler(Exception.class)
	@ResponseBody
	public Map<String, String> others(Exception e) {
		e.printStackTrace();
		return handle(new Exception("Internal Error"));
	}

	private Map<String, String> handle(Exception e) {
		String tResponse = ThreadContext.getContext().get();
		Message<String> message = new Message<String>().setError().setMessage(e.getMessage());
		Map<String, String> response = new HashMap<>();
		if (tResponse != null && !tResponse.isEmpty()) response.put("T", tResponse);
		response.put("M", message.toJson());
		return response;
	}
}
