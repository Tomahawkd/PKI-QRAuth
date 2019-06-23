package io.tomahawkd.pki.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class ControllerExceptionHandler {

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Malformed Json")
	@ExceptionHandler(MalformedJsonException.class)
	public void malformedJson() {

	}
}
