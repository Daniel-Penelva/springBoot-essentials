package com.daniel.springbootessentials.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException{
   
    public BadRequestException(String message){
        super(message);
    }
}

/* Estamos usando HttpStatus.BAD_REQUEST, que corresponde ao status 400 Bad Request. Que define uma requisição é inválida ou malformada. */