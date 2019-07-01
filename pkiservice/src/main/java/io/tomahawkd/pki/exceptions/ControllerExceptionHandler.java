package io.tomahawkd.pki.exceptions;

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

	@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR, reason = "Cipher error")
	@ExceptionHandler(CipherErrorException.class)
	public void cipherIssue(Exception e) {

	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Malformed Base64 value")
	@ExceptionHandler(Base64EncodeException.class)
	public void base64Issue(Exception e) {

	}
}
