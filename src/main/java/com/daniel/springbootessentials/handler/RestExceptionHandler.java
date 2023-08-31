package com.daniel.springbootessentials.handler;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.daniel.springbootessentials.exception.BadRequestException;
import com.daniel.springbootessentials.exception.BadRequestExceptionDetails;

@ControllerAdvice
public class RestExceptionHandler {

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<BadRequestExceptionDetails> handlerBadRequestException(BadRequestException exception) {
        
        return new ResponseEntity<>(
            BadRequestExceptionDetails.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .tittle("Bad Request Exception, Check documentation")
            .details(exception.getMessage())
            .developerMessage(exception.getClass().getName())
            .build(), HttpStatus.BAD_REQUEST);
    }
}

/* Caso tenha uma exceção do tipo BadRequestException vai ser utilizado pelo controller o @ExceptionHandler retornando o valor que está neste 
método */