package io.tomahawkd.pki.exceptions.api;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class ApiExceptionHandler {

	@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR, reason = "Cipher error")
	@ExceptionHandler(CipherErrorException.class)
	public void cipherIssue(Exception e) {

	}
}
