package com.daniel.springbootessentials.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.service.AnimeService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("animes")

@AllArgsConstructor // Lombok - Para injeção de dependência (gera construtor)
public class AnimeController {

    private AnimeService animeService;

    // Listar todos os animes: http://localhost:8080/animes
    @GetMapping
    public List<Anime> list() {
        return animeService.listAll();
    }

    // Buscar por id o anime: http://localhost:8080/animes/{id}
    @GetMapping(path = "/{id}")
    public ResponseEntity<Anime> findById(@PathVariable("id") Long id) {
        return new ResponseEntity(animeService.findById(id), HttpStatus.OK);
    }

    // Salvar anime - http://localhost:8080/animes
    @PostMapping
    @ResponseBody
    public ResponseEntity<Anime> save(@RequestBody Anime anime) {
        return new ResponseEntity<>(animeService.save(anime), HttpStatus.CREATED);
    }
}
