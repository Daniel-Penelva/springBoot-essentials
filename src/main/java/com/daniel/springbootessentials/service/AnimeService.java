package com.daniel.springbootessentials.service;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.mapper.AnimeMapper;
import com.daniel.springbootessentials.repository.AnimeRepository;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.requests.AnimePutRequestBody;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AnimeService {

    /* Responsável pela regra de negócio */

    private final AnimeRepository animeRepository;

    // Buscar todos os animes
    public List<Anime> listAll() {
        return animeRepository.findAll();
    }

    // Buscar por id anime
    public Anime findByIdOrThrowBadRequestException(Long id) {
        // findById - retorna um Optional
        return animeRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Anime not found"));
    }

    // Salvar anime
    public Anime save(AnimePostRequestBody animePostRequestBody) {
        
        return animeRepository.save(AnimeMapper.INSTANCE.toAnime(animePostRequestBody));
        //animeRepository.save(AnimeMapperImpl.INSTANCE.toAnime(animePostRequestBody));
    }

    // Deletar anime
    public void delete(Long id) {
        animeRepository.delete(findByIdOrThrowBadRequestException(id));
    }

    // Alterar anime
    public void replace(AnimePutRequestBody animePutRequestBody) {

        Anime savedAnime = findByIdOrThrowBadRequestException(animePutRequestBody.getId());

        Anime anime = AnimeMapper.INSTANCE.toAnime(animePutRequestBody);
        anime.setId(savedAnime.getId());
        
        animeRepository.save(anime);
    }

}
