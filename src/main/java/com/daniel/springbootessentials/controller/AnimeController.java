package com.daniel.springbootessentials.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.daniel.springbootessentials.domain.Anime;

@RestController
@RequestMapping("anime/")
public class AnimeController {
    
    // http://localhost:8080/anime/list
	@GetMapping(path = "list")
	public List<Anime> list() {
		return List.of(new Anime("DBZ"), new Anime("Naruto"));
	}

}
