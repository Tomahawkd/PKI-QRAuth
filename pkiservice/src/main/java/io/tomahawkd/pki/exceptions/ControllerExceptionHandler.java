package io.tomahawkd.pki.exceptions;

import com.google.gson.Gson;
import io.tomahawkd.pki.model.SystemLogModel;
import io.tomahawkd.pki.service.SystemLogService;
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
	public String malformedJson(Exception e) {
		return handle(e);
	}

	@ResponseStatus(HttpStatus.NOT_FOUND)
	@ExceptionHandler({NullPointerException.class, NotFoundException.class})
	@ResponseBody
	public String notFound(Exception e) {
		return handle(e);

	}

	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	@ExceptionHandler(CipherErrorException.class)
	@ResponseBody
	public String cipherIssue(Exception e) {
		return handle(e);

	}

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(Base64EncodeException.class)
	@ResponseBody
	public String base64Issue(Exception e) {
		return handle(e);

	}

	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	@ExceptionHandler(Exception.class)
	@ResponseBody
	public String others(Exception e) {
		e.printStackTrace();
		return handle(new Exception("Internal Error"));
	}

	private String handle(Exception e) {

		Map<String, String> response = new HashMap<>();

		Message<String> message = new Message<String>().setError().setMessage("Unknown error");

		if (e == null) {
			response.put("M", message.toJson());
			return new Gson().toJson(response);
		}

		message.setMessage(e.getMessage() == null ? message.getMessage() : e.getMessage());

		SystemLogService log = ThreadContext.getLogContext().get();

		if (log != null) {
			log.insertLogRecord(ControllerExceptionHandler.class.getName(),
					"handle", SystemLogModel.FATAL,
					e.getClass().getName() + ": " + message.getMessage());

			String tResponse = ThreadContext.getTimeContext().get();

			if (tResponse != null && !tResponse.isEmpty()) response.put("T", tResponse);
		}

		response.put("M", message.toJson());
		return new Gson().toJson(response);
	}
}
