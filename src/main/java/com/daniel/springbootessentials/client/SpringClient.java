package com.daniel.springbootessentials.client;

import java.util.Arrays;
import java.util.List;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import com.daniel.springbootessentials.domain.Anime;

public class SpringClient {

    public static void main(String[] args) {

        ResponseEntity<Anime> entity = new RestTemplate().getForEntity("http://localhost:8080/animes/{id}", Anime.class,
                3);
        System.out.println(entity);

        Anime object = new RestTemplate().getForObject("http://localhost:8080/animes/6", Anime.class);
        System.out.println(object);

        Anime[] animes = new RestTemplate().getForObject("http://localhost:8080/animes/all", Anime[].class);
        System.out.println(Arrays.toString(animes));

        ResponseEntity<List<Anime>> exchange = new RestTemplate().exchange("http://localhost:8080/animes/all",
                HttpMethod.GET, null,
                new ParameterizedTypeReference<List<Anime>>() {
                });
        System.out.println(exchange.getBody());

        // Esse método (Anime.builder()) retorna um construtor especial chamado de builder que é usado para criar objetos da classe Anime de maneira mais conveniente e legível.
        Anime kingdom = Anime.builder().name("kingdom").build();
        Anime kingdomSave = new RestTemplate().postForObject("http://localhost:8080/animes/", kingdom, Anime.class);
        System.out.println("Anime salvo: " + kingdomSave);

        // Exemplo utilizando exchange
        Anime samuraiChamploo = Anime.builder().name("Samurai Champloo").build();
        ResponseEntity<Anime> samuraiChamplooSave = new RestTemplate().exchange("http://localhost:8080/animes/",
                HttpMethod.POST, new HttpEntity<>(samuraiChamploo), Anime.class);

        System.out.println("Anime salvo: " + samuraiChamplooSave);

        // Exemplo com HttpHeaders
        Anime boruto = Anime.builder().name("Boruto").build();
        ResponseEntity<Anime> borutoSave = new RestTemplate().exchange("http://localhost:8080/animes/",
                HttpMethod.POST, new HttpEntity<>(boruto, createJSonHeader()), Anime.class);
        
        System.out.println("Anime salvo: " + borutoSave); 
        

        // Rest Template PUT (atualizar) utilizando o exchange
        Anime animeToBeUpdate = samuraiChamplooSave.getBody();
        animeToBeUpdate.setName("samuraiChamploo Up");
       
        ResponseEntity<Void> samuraiChamplooUpdate = new RestTemplate().exchange("http://localhost:8080/animes/",
                HttpMethod.PUT, new HttpEntity<>(animeToBeUpdate), Void.class);

        System.out.println("Anime atualizado: " + samuraiChamplooUpdate);

         // Rest Template DELETE (deletar) utilizando o exchange
         ResponseEntity<Void> samuraiChamplooDelete = new RestTemplate().exchange("http://localhost:8080/animes/{id}",
                HttpMethod.DELETE, null, Void.class, animeToBeUpdate.getId());

         System.out.println("Anime Deletado: " + samuraiChamplooDelete);
    }

    private static HttpHeaders createJSonHeader(){
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);
        return httpHeaders;
    }
}
