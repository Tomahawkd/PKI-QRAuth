package io.tomahawkd.simpleserver.exceptions.base;

import io.tomahawkd.simpleserver.exceptions.MalformedJsonException;
import io.tomahawkd.simpleserver.exceptions.NotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class ControllerExceptionHandler {

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Malformed Json")
	@ExceptionHandler(MalformedJsonException.class)
	public void malformedJson(Exception e) {

	}

	@ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "Not found")
	@ExceptionHandler({NullPointerException.class, NotFoundException.class})
	public void notFound(Exception e) {

	}
}
