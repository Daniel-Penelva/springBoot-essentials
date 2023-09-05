package com.daniel.springbootessentials.handler;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.daniel.springbootessentials.exception.BadRequestException;
import com.daniel.springbootessentials.exception.BadRequestExceptionDetails;
import com.daniel.springbootessentials.exception.ValidationExceptionDetails;

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

    // Exception MethodArgumentNotValidException - Gera exception se anime for null ou " ".
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationExceptionDetails> handlerMethodArgumentNotValidException(
            MethodArgumentNotValidException exception) {

        List<FieldError> fieldErrors = exception.getBindingResult().getFieldErrors();
        String fields = fieldErrors.stream().map(FieldError::getField).collect(Collectors.joining(", "));
        String fieldsMessage = fieldErrors.stream().map(FieldError::getDefaultMessage).collect(Collectors.joining(", "));

         return new ResponseEntity<>(
            ValidationExceptionDetails.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .tittle("Bad Request Exception, Check documentation")
            .details("Check the filed(s) error")
            .developerMessage(exception.getClass().getName())
            .field(fields)
            .fieldMessage(fieldsMessage)
            .build(), HttpStatus.BAD_REQUEST);
    }
}

/*
 * Caso tenha uma exceção do tipo BadRequestException vai ser utilizado pelo
 * controller o @ExceptionHandler retornando o valor que está neste
 * método
 */