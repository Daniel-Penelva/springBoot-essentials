package com.daniel.springbootessentials.client;

import java.util.Arrays;
import java.util.List;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
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

    }
}
