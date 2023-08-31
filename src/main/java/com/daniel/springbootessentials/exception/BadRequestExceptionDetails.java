package com.daniel.springbootessentials.exception;

import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BadRequestExceptionDetails {

    private String tittle;
    private int status;
    private String details;
    private String developerMessage;
    private LocalDateTime timestamp;
    
}

/* Temos que falar para o controller que sempre que tiver uma exceção do tipo BadRequestException vai ser preciso utilizar o método 
 * "handlerBadRequestException" que está dentro da classe RestExceptionHandler (pacote Handler) onde possui essas propriedades (tittle,
 * status, details, developerMessage e timestamp) que serão mostrados para o usuário.
 */
