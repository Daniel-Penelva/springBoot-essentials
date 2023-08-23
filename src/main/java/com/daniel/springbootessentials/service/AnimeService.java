package com.daniel.springbootessentials.service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.daniel.springbootessentials.domain.Anime;

@Service
public class AnimeService {

    /* Responsável pela regra de negócio */

    private static List<Anime> animes;

    static {
        animes = new ArrayList<>(List.of(new Anime(1L, "DBZ"), new Anime(2L, "Naruto"),
                new Anime(3L, "Cavalheiros dos Zodíacos")));
    }

    // Buscar todos os animes
    public List<Anime> listAll() {
        return animes;
    }

    // Buscar por id anime
    public Anime findById(Long id) {
        return animes.stream()
                .filter(anime -> anime.getId().equals(id))
                .findFirst().orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Anime not found"));
    }

    // Salvar anime
    public Anime save(Anime anime){
        anime.setId(ThreadLocalRandom.current().nextLong(3, 100));
        animes.add(anime);
        return anime;
    }

    // Deletar anime
    public void delete(Long id){
        animes.remove(findById(id));
    }

    // Alterar anime
    public void replace(Anime anime){
        delete(anime.getId());
        animes.add(anime);
    }

}
