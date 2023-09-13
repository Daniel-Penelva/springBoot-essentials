package com.daniel.springbootessentials.service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

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
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.exception.BadRequestException;
import com.daniel.springbootessentials.repository.AnimeRepository;
import com.daniel.springbootessentials.util.AnimeCreator;
import com.daniel.springbootessentials.util.AnimePostRequestBodyCreator;
import com.daniel.springbootessentials.util.AnimePutRequestBodyCreator;

@ExtendWith(SpringExtension.class)
public class AnimeServiceTest {
   
    @InjectMocks
    private AnimeService animeService;

    @Mock
    private AnimeRepository animeRepositoryMock;

    @BeforeEach
    void SetUp(){
      PageImpl<Anime> animePage = new PageImpl<>(List.of(AnimeCreator.createValidAnime())); 

      BDDMockito.when(animeRepositoryMock.findAll(ArgumentMatchers.any(PageRequest.class))).thenReturn(animePage); // com paginação

      BDDMockito.when(animeRepositoryMock.findAll()).thenReturn(List.of(AnimeCreator.createValidAnime())); // sem paginação

      // Buscar anime por id  
      BDDMockito.when(animeRepositoryMock.findById(ArgumentMatchers.anyLong())).thenReturn(Optional.of(AnimeCreator.createValidAnime())); // sem paginação

      // Buscar anime por nome
      BDDMockito.when(animeRepositoryMock.findByName(ArgumentMatchers.anyString())).thenReturn(List.of(AnimeCreator.createValidAnime()));
      
      // Salvar e update anime
      BDDMockito.when(animeRepositoryMock.save(ArgumentMatchers.any(Anime.class))).thenReturn(AnimeCreator.createValidAnime());

      // Deletar anime - tb retorna um void no método delete() do AnimeService.
      BDDMockito.doNothing().when(animeRepositoryMock).delete(ArgumentMatchers.any(Anime.class));
    }


    // Teste para listar anime com paginação
    @Test
    @DisplayName("List returns list of anime inside page object when successful")
    void listAll_ReturnsListOfanimesInsidePageObject_whenSuccessful() {

        String expectedName = AnimeCreator.createValidAnime().getName();

        Page<Anime> animePage = animeService.listAll(PageRequest.of(1, 1));

        Assertions.assertThat(animePage).isNotNull();
        Assertions.assertThat(animePage).isNotEmpty().hasSize(1);
        Assertions.assertThat(animePage.toList().get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para listar anime sem paginação
    @Test
    @DisplayName("List returns list of anime when successful")
    void listAll_ReturnsListOfanimes_whenSuccessful() {

        String expectedName = AnimeCreator.createValidAnime().getName();

        List<Anime> listAnimes = animeService.listAllNonPageable();

        Assertions.assertThat(listAnimes).isNotNull();
        Assertions.assertThat(listAnimes).isNotEmpty().hasSize(1);
        Assertions.assertThat(listAnimes.get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para buscar anime por id
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessful() {

       Long expectedId = AnimeCreator.createValidAnime().getId();

       Anime anime = animeService.findByIdOrThrowBadRequestException(1L);

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }

    // Teste para buscar anime por nome
    @Test
    @DisplayName("findByNome returns a list of anime when successful")
    void findByNome_ReturnsListOfAnime_whenSuccessful() {

        String expectedName = AnimeCreator.createValidAnime().getName();

        List<Anime> listAnimes = animeService.findByName("anime");

        Assertions.assertThat(listAnimes).isNotNull();
        Assertions.assertThat(listAnimes).isNotEmpty().hasSize(1);
        Assertions.assertThat(listAnimes.get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para buscar anime por nome e não encontrar 
    @Test
    @DisplayName("findByNome returns an empty list of anime is not found")
    void findByNome_ReturnsEmptyListOfAnime_whenIsNotFound() {

       BDDMockito.when(animeRepositoryMock.findByName(ArgumentMatchers.anyString()))
       .thenReturn(Collections.emptyList()); 

       List<Anime> listAnimes = animeService.findByName("anime");

        Assertions.assertThat(listAnimes).isNotNull();
        Assertions.assertThat(listAnimes).isEmpty();
    }

    // Teste para salvar anime 
    @Test
    @DisplayName("save returns anime when successful")
    void save_ReturnsAnime_whenSuccessful() {

       Anime anime = animeService.save(AnimePostRequestBodyCreator.createAnimePostRequestBody());

        Assertions.assertThat(anime).isNotNull().isEqualTo(AnimeCreator.createValidAnime());  
    }

    // Teste para atualizar anime 
    @Test
    @DisplayName("replace update anime when successful")
    void replace_UpdatesAnime_whenSuccessful() {

        Assertions.assertThatCode(() -> animeService.replace(AnimePutRequestBodyCreator.createAnimePutRequestBody())).doesNotThrowAnyException();
    }

    // Teste para deletar anime por id
    @Test
    @DisplayName("delete removes anime when successful")
    void delete_RemovesAnime_whenSuccessful() {

       Assertions.assertThatCode(() -> animeService.delete(1L)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("findByIdOrThrowBadRequestException throws BadRequstException when anime is not found")
    void findByIdOrThrowBadRequestException_ThrowsBadRequstException_whenSuccessful() {

        BDDMockito.when(animeRepositoryMock.findById(ArgumentMatchers.anyLong())).thenReturn(Optional.empty());

        Assertions.assertThatExceptionOfType(BadRequestException.class)
        .isThrownBy(() -> animeService.findByIdOrThrowBadRequestException(1L));
    }
}
