package com.daniel.springbootessentials.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.daniel.springbootessentials.domain.Anime;

@Service
public class AnimeService {

    /* Responsável pela regra de negócio */
    public List<Anime> listAll() {
		return List.of(new Anime(1L, "DBZ"), new Anime(2L, "Naruto"), new Anime(3L, "Cavalheiros dos Zodíacos"));
	}

}
