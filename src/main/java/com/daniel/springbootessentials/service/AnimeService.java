package com.daniel.springbootessentials.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.exception.BadRequestException;
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
     @Transactional(readOnly = true)
    public Page<Anime> listAll(Pageable pageable) {
        return animeRepository.findAll(pageable);
    }

    // Buscar todos os animes sem paginação 
    public List<Anime> listAllNonPageable(){
        return animeRepository.findAll();
    }

    // Buscar por id anime
    @Transactional(readOnly = true)
    public Anime findByIdOrThrowBadRequestException(Long id) {
        // findById - retorna um Optional
        return animeRepository.findById(id)
                .orElseThrow(() -> new BadRequestException("Anime not found"));
    }

    // Salvar anime
    @Transactional
    public Anime save(AnimePostRequestBody animePostRequestBody) {
        
        return animeRepository.save(AnimeMapper.INSTANCE.toAnime(animePostRequestBody));
        //animeRepository.save(AnimeMapperImpl.INSTANCE.toAnime(animePostRequestBody));
    }

    // Deletar anime
    @Transactional
    public void delete(Long id) {
        animeRepository.delete(findByIdOrThrowBadRequestException(id));
    }

    // Alterar anime
    @Transactional
    public void replace(AnimePutRequestBody animePutRequestBody) {

        Anime savedAnime = findByIdOrThrowBadRequestException(animePutRequestBody.getId());

        Anime anime = AnimeMapper.INSTANCE.toAnime(animePutRequestBody);
        anime.setId(savedAnime.getId());
        
        animeRepository.save(anime);
    }

    // Buscar todos os animes por nome
    @Transactional(readOnly = true)
    public List<Anime> findByName(String name) {
        return animeRepository.findByName(name);
    }

}
