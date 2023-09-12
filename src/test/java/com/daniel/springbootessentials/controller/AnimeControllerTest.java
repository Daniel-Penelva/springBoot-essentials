package com.daniel.springbootessentials.controller;

import static org.mockito.ArgumentMatchers.isNotNull;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.service.AnimeService;
import com.daniel.springbootessentials.util.AnimeCreator;
import com.daniel.springbootessentials.util.AnimePostRequestBodyCreator;

@ExtendWith(SpringExtension.class)
public class AnimeControllerTest {

    @InjectMocks
    private AnimeController animeController;

    @Mock
    private AnimeService animeService;

    @BeforeEach
    void SetUp(){
      PageImpl<Anime> animePage = new PageImpl<>(List.of(AnimeCreator.createValidAnime())); 

      BDDMockito.when(animeService.listAll(ArgumentMatchers.any())).thenReturn(animePage); // com paginação

      BDDMockito.when(animeService.listAllNonPageable()).thenReturn(List.of(AnimeCreator.createValidAnime())); // sem paginação

      // Buscar anime por id  
      BDDMockito.when(animeService.findByIdOrThrowBadRequestException(ArgumentMatchers.anyLong())).thenReturn(AnimeCreator.createValidAnime()); // sem paginação

      // Buscar anime por nome
      BDDMockito.when(animeService.findByName(ArgumentMatchers.anyString())).thenReturn(List.of(AnimeCreator.createValidAnime()));
      
      // Salvar anime
      BDDMockito.when(animeService.save(ArgumentMatchers.any(AnimePostRequestBody.class))).thenReturn(AnimeCreator.createValidAnime()); 
    }


    // Listar anime com paginação
    @Test
    @DisplayName("List returns list of anime inside page object when successful")
    void list_ReturnsListOfanimesInsidePageObject_whenSuccessful() {

        String expectedName = AnimeCreator.createValidAnime().getName();

        Page<Anime> animePage = animeController.list(null).getBody();

        Assertions.assertThat(animePage).isNotNull();
        Assertions.assertThat(animePage).isNotEmpty().hasSize(1);
        Assertions.assertThat(animePage.toList().get(0).getName()).isEqualTo(expectedName);
    }

    // Listar anime sem paginação
    @Test
    @DisplayName("List returns list of anime when successful")
    void listAll_ReturnsListOfanimes_whenSuccessful() {

        String expectedName = AnimeCreator.createValidAnime().getName();

       List<Anime> listAnimes = animeController.listAll().getBody();

        Assertions.assertThat(listAnimes).isNotNull();
        Assertions.assertThat(listAnimes).isNotEmpty().hasSize(1);
        Assertions.assertThat(listAnimes.get(0).getName()).isEqualTo(expectedName);
    }

    // Buscar anime por id
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessful() {

       Long expectedId = AnimeCreator.createValidAnime().getId();

       Anime anime = animeController.findById(1L).getBody();

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }

    // Buscar anime por nome
    @Test
    @DisplayName("findByNome returns a list of anime when successful")
    void findByNome_ReturnsListOfAnime_whenSuccessful() {

       String expectedName = AnimeCreator.createValidAnime().getName();

       List<Anime> listAnimes = animeController.findByName("anime").getBody();

        Assertions.assertThat(listAnimes).isNotNull();
        Assertions.assertThat(listAnimes).isNotEmpty().hasSize(1);
        Assertions.assertThat(listAnimes.get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para buscar anime por nome e não encontrar 
    @Test
    @DisplayName("findByNome returns an empty list of anime is not found")
    void findByNome_ReturnsEmptyListOfAnime_whenIsNotFound() {

       BDDMockito.when(animeService.findByName(ArgumentMatchers.anyString()))
       .thenReturn(Collections.emptyList()); 

       List<Anime> listAnimes = animeController.findByName("anime").getBody();

        Assertions.assertThat(listAnimes).isNotNull();
        Assertions.assertThat(listAnimes).isEmpty();
    }

    // salvar anime 
    @Test
    @DisplayName("save returns anime when successful")
    void save_ReturnsAnime_whenSuccessful() {

       Anime anime = animeController.save(AnimePostRequestBodyCreator.createAnimePostRequestBody()).getBody();

        Assertions.assertThat(anime).isNotNull().isEqualTo(AnimeCreator.createValidAnime());  
    }
}
