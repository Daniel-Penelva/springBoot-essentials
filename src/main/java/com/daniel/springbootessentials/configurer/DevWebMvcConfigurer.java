package com.daniel.springbootessentials.configurer;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class DevWebMvcConfigurer implements WebMvcConfigurer {

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {

        PageableHandlerMethodArgumentResolver pageHandler = new PageableHandlerMethodArgumentResolver();
        pageHandler.setFallbackPageable(PageRequest.of(0, 5));
        resolvers.add(pageHandler);
    }
}

/**
 * Explicação passo a passo do script:
 * 
 * 1. `@Configuration`: Esta anotação marca a classe como uma classe de configuração do Spring. Isso significa que ela contém configurações 
 *     personalizadas para o aplicativo Spring.
 * 
 * 2. `public class DevWebMvcConfigurer implements WebMvcConfigurer`: A classe `DevWebMvcConfigurer` é declarada e implementa a interface 
 *    `WebMvcConfigurer`, o que a torna responsável por configurar o comportamento do Spring MVC.
 * 
 * 3. `@Override`: Esta anotação indica que o método a seguir está substituindo um método da interface `WebMvcConfigurer`.
 * 
 * 4. `public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers)`: Este método é chamado pelo Spring MVC durante a 
 *     inicialização para adicionar resolutores de argumentos personalizados. Ele recebe uma lista de resolutores de argumentos (`resolvers`) 
 *     como parâmetro.
 * 
 * 5. `PageableHandlerMethodArgumentResolver pageHandler = new PageableHandlerMethodArgumentResolver();`: Aqui, um novo objeto 
 *    `PageableHandlerMethodArgumentResolver` é criado. Esse resolutor é responsável por processar argumentos relacionados à paginação em 
 *     solicitações HTTP.
 * 
 * 6. `pageHandler.setFallbackPageable(PageRequest.of(0, 5));`: Este trecho configura um valor padrão (fallback) para a paginação. Se nenhum 
 *     valor de paginação for fornecido na solicitação, o `PageableHandlerMethodArgumentResolver` usará esse valor como padrão. Neste caso, está 
 *     definido para a primeira página (0) com um tamanho de página de 5.
 * 
 * 7. `resolvers.add(pageHandler);`: O resolutor de argumentos `pageHandler` configurado anteriormente é adicionado à lista de resolutores 
 *    `resolvers`. Isso significa que o Spring MVC usará este resolutor para tratar argumentos de paginação em solicitações HTTP.
 * 
 * Em resumo, este script configura um resolutor de argumentos personalizado chamado `PageableHandlerMethodArgumentResolver` que lida com 
 * argumentos relacionados à paginação em solicitações HTTP. Ele também define um valor padrão para a paginação, caso nenhum valor seja 
 * especificado na solicitação. Isso é útil para facilitar a paginação em APIs RESTful ou aplicativos da web que fazem uso de recursos paginados.
*/