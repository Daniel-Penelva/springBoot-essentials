package com.daniel.springbootessentials.requests;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.hibernate.validator.constraints.URL;

import lombok.Data;

@Data
public class AnimePostRequestBody {
    
    @NotEmpty(message = "The anime name cannot be empty")
    @NotNull(message = "The anime name cannot be null")
    private String name;

    // Para testar a validação de campo (handler) - Mais um campo para testar que vai ser gerado uma lista de Fields
    @URL(message = "The URL is not valid")
    private String url;
}
