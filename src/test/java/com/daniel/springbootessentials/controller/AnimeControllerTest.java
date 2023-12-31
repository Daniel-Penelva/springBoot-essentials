package com.daniel.springbootessentials.controller;

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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.requests.AnimePutRequestBody;
import com.daniel.springbootessentials.service.AnimeService;
import com.daniel.springbootessentials.util.AnimeCreator;
import com.daniel.springbootessentials.util.AnimePostRequestBodyCreator;
import com.daniel.springbootessentials.util.AnimePutRequestBodyCreator;

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

      // Atualizar anime - lembrando que esse método replace no AnimeService retorna void, logo vai ser usado o método doNothing() para que o método não faça nada.
      BDDMockito.doNothing().when(animeService).replace(ArgumentMatchers.any(AnimePutRequestBody.class));

      // Deletar anime - tb retorna um void no método delete() do AnimeService.
      BDDMockito.doNothing().when(animeService).delete(ArgumentMatchers.anyLong());
    }


    // Teste para listar anime com paginação
    @Test
    @DisplayName("List returns list of anime inside page object when successful")
    void list_ReturnsListOfanimesInsidePageObject_whenSuccessful() {

        String expectedName = AnimeCreator.createValidAnime().getName();

        Page<Anime> animePage = animeController.list(null).getBody();

        Assertions.assertThat(animePage).isNotNull();
        Assertions.assertThat(animePage).isNotEmpty().hasSize(1);
        Assertions.assertThat(animePage.toList().get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para listar anime sem paginação
    @Test
    @DisplayName("List returns list of anime when successful")
    void listAll_ReturnsListOfanimes_whenSuccessful() {

        String expectedName = AnimeCreator.createValidAnime().getName();

       List<Anime> listAnimes = animeController.listAll().getBody();

        Assertions.assertThat(listAnimes).isNotNull();
        Assertions.assertThat(listAnimes).isNotEmpty().hasSize(1);
        Assertions.assertThat(listAnimes.get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para buscar anime por id
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessful() {

       Long expectedId = AnimeCreator.createValidAnime().getId();

       Anime anime = animeController.findById(1L).getBody();

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }

    // Teste para buscar anime por nome
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

    // Teste para salvar anime 
    @Test
    @DisplayName("save returns anime when successful")
    void save_ReturnsAnime_whenSuccessful() {

       Anime anime = animeController.save(AnimePostRequestBodyCreator.createAnimePostRequestBody()).getBody();

        Assertions.assertThat(anime).isNotNull().isEqualTo(AnimeCreator.createValidAnime());  
    }

    // Teste para atualizar anime 
    @Test
    @DisplayName("replace update anime when successful")
    void replace_UpdatesAnime_whenSuccessful() {

        Assertions.assertThatCode(() -> animeController.replace(AnimePutRequestBodyCreator.createAnimePutRequestBody())).doesNotThrowAnyException();

       ResponseEntity<Void> entity = animeController.replace(AnimePutRequestBodyCreator.createAnimePutRequestBody());

        Assertions.assertThat(entity).isNotNull();  
        Assertions.assertThat(entity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    // Teste para deletar anime por id
    @Test
    @DisplayName("delete removes anime when successful")
    void delete_RemovesAnime_whenSuccessful() {

       Assertions.assertThatCode(() -> animeController.delete(1L)).doesNotThrowAnyException();

       ResponseEntity<Void> entity = animeController.delete(1L);

        Assertions.assertThat(entity).isNotNull();  
        Assertions.assertThat(entity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }
}
