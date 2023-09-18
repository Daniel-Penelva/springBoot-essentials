package com.daniel.springbootessentials.integration;

import java.util.List;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.repository.AnimeRepository;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.util.AnimeCreator;
import com.daniel.springbootessentials.util.AnimePostRequestBodyCreator;
import com.daniel.springbootessentials.wrapper.PageableResponse;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase
public class AnimeControllerIT {

    @Autowired
    private TestRestTemplate testRestTemplate;

    @Autowired
    private AnimeRepository animeRepository;

    @LocalServerPort
    private int port;

    @Test
    @DisplayName("List returns list of anime inside page object when successful")
    void list_ReturnsListOfanimesInsidePageObject_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        String expectedName = savedAnime.getName();

        PageableResponse<Anime> animePage = testRestTemplate.exchange("/animes", HttpMethod.GET, null,
                new ParameterizedTypeReference<PageableResponse<Anime>>() {
                }).getBody();

        Assertions.assertThat(animePage).isNotNull();
        Assertions.assertThat(animePage.toList()).isNotEmpty().hasSize(1);
        Assertions.assertThat(animePage.toList().get(0).getName()).isEqualTo(expectedName);
    }
    
    // Teste para listar anime sem paginação
    @Test
    @DisplayName("List returns list of anime when successful")
    void listAll_ReturnsListOfanimes_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        String expectedName = savedAnime.getName();

        List<Anime> animes = testRestTemplate.exchange("/animes/all", HttpMethod.GET, null,
                new ParameterizedTypeReference<List<Anime>>() {
                }).getBody();

        Assertions.assertThat(animes).isNotNull().isNotEmpty().hasSize(1);
        Assertions.assertThat(animes.get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para buscar anime por id
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessful() {

       Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());
       
       Long expectedId = savedAnime.getId();

       Anime anime = testRestTemplate. getForObject("/animes/{id}", Anime.class, expectedId);

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }
    
    // Teste para salvar anime 
    @Test
    @DisplayName("save returns anime when successful")
    void save_ReturnsAnime_whenSuccessful() {

       AnimePostRequestBody animePostRequestBody = AnimePostRequestBodyCreator.createAnimePostRequestBody();

        ResponseEntity<Anime> animeResponseEntity = testRestTemplate.postForEntity("/animes/", animePostRequestBody, Anime.class);

        Assertions.assertThat(animeResponseEntity).isNotNull();
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.CREATED);  
        Assertions.assertThat(animeResponseEntity.getBody()).isNotNull();
        Assertions.assertThat(animeResponseEntity.getBody().getId()).isNotNull();
    }

    // Teste para buscar anime por nome
    @Test
    @DisplayName("findByNome returns a list of anime when successful")
    void findByNome_ReturnsListOfAnime_whenSuccessful() {
        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());
        String expectedName = savedAnime.getName();
    
        ResponseEntity<List<Anime>> response = testRestTemplate.exchange("/animes/find/{name}", HttpMethod.GET, null, 
                new ParameterizedTypeReference<List<Anime>>() {}, expectedName);
    
        List<Anime> animes = response.getBody();
    
        Assertions.assertThat(animes).isNotNull().isNotEmpty().hasSize(1);
        Assertions.assertThat(animes.get(0).getName()).isEqualTo(expectedName);
    }    

    // Teste para buscar anime por nome não encontrado 
    @Test
    @DisplayName("findByNome returns an empty list of anime is not found")
    void findByNome_ReturnsEmptyListOfAnime_whenIsNotFound() {

     String url = String.format("/animes/find/dbz");

    ResponseEntity<List<Anime>> response = testRestTemplate.exchange(
        url, HttpMethod.GET, null, new ParameterizedTypeReference<List<Anime>>() {}
    );

    // Verificações
    Assertions.assertThat(response.getStatusCodeValue()).isEqualTo(HttpStatus.OK.value());
    Assertions.assertThat(response.getBody()).isNotNull().isEmpty();
    }

}