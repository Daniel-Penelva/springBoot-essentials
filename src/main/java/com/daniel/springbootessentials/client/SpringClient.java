package com.daniel.springbootessentials.client;

import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import com.daniel.springbootessentials.domain.Anime;

public class SpringClient {

    public static void main(String[] args) {

        ResponseEntity<Anime> entity = new RestTemplate().getForEntity("http://localhost:8080/animes/6", Anime.class);
        System.out.println(entity);

        Anime object = new RestTemplate().getForObject("http://localhost:8080/animes/6", Anime.class);
        System.out.println(object);
    }
}
