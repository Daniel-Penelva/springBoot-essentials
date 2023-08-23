package com.daniel.springbootessentials.controller;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.service.AnimeService;
import com.daniel.springbootessentials.util.DateUtil;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

@RestController
@RequestMapping("animes")
@Log4j2
@AllArgsConstructor // Lombok - Para injeção de dependência (gera construtor)
public class AnimeController {

    private DateUtil dateUtil;
    private AnimeService animeService;

    // http://localhost:8080/animes
    @GetMapping
    public List<Anime> list() {
        return animeService.listAll();
    }

    // http://localhost:8080/anime/formatodata
    @GetMapping(path = "formatodata")
    private Object formatLocalDateTimeToDatabaseStyle(LocalDateTime now) {

        log.info(dateUtil.formatLocalDateTimeToDatabaseStyle(LocalDateTime.now()));

        return dateUtil.formatLocalDateTimeToDatabaseStyle(LocalDateTime.now());
    }

}
