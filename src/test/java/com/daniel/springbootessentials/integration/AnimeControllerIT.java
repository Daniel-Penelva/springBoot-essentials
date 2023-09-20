package com.daniel.springbootessentials.integration;

import java.util.List;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.domain.CustomUserDetails;
import com.daniel.springbootessentials.repository.AnimeRepository;
import com.daniel.springbootessentials.repository.CustomUserDetailsRepository;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.util.AnimeCreator;
import com.daniel.springbootessentials.util.AnimePostRequestBodyCreator;
import com.daniel.springbootessentials.wrapper.PageableResponse;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class AnimeControllerIT {

    @Autowired
    @Qualifier(value = "testRestTemplateRoleAdmin")
    private TestRestTemplate testRestTemplateRoleAdmin;

    @Autowired
    @Qualifier(value = "testRestTemplateRoleUser")
    private TestRestTemplate testRestTemplateRoleUser;

    @Autowired
    private AnimeRepository animeRepository;

    @Autowired
    private CustomUserDetailsRepository customUserDetailsRepository;


    private static CustomUserDetails ADMIN = CustomUserDetails.builder()
            .name("Daniel")
            .password("{bcrypt}$2a$10$0eykM.E9h17yruE6rkjrrezEUysVWasDjekzXto7cCk9wABM0cPLG")
            .username("daniel")
            .authorities("ROLE_ADMIN, ROLE_USER")
            .build();

    private static CustomUserDetails USER = CustomUserDetails.builder()
            .name("Biana")
            .password("{bcrypt}$2a$10$0eykM.E9h17yruE6rkjrrezEUysVWasDjekzXto7cCk9wABM0cPLG")
            .username("biana")
            .authorities("ROLE_USER")
            .build();

    @TestConfiguration
    @Lazy
    static class Config{
       
        @Bean(name = "testRestTemplateRoleAdmin")
        public TestRestTemplate testRestTemplateRoleAdminCreator(@Value("${local.server.port}") int port){
            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder()
                    .rootUri("http://localhost:" + port)
                    .basicAuthentication("daniel", "admin");
                    
            return new TestRestTemplate(restTemplateBuilder);
        }

        @Bean(name = "testRestTemplateRoleUser")
        public TestRestTemplate testRestTemplateRoleUserCreator(@Value("${local.server.port}") int port){
            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder()
                    .rootUri("http://localhost:" + port)
                    .basicAuthentication("biana", "admin");
                    
            return new TestRestTemplate(restTemplateBuilder);
        }
    }

    @Test
    @DisplayName("List returns list of anime inside page object when successful")
    void list_ReturnsListOfanimesInsidePageObject_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();

        PageableResponse<Anime> animePage = testRestTemplateRoleUser.exchange("/animes", HttpMethod.GET, null,
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

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();

        List<Anime> animes = testRestTemplateRoleUser.exchange("/animes/all", HttpMethod.GET, null,
                new ParameterizedTypeReference<List<Anime>>() {
                }).getBody();

        Assertions.assertThat(animes).isNotNull().isNotEmpty().hasSize(1);
        Assertions.assertThat(animes.get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para buscar anime por id não autenticado
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessful() {

       Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

       customUserDetailsRepository.save(USER);
       
       Long expectedId = savedAnime.getId();

       Anime anime = testRestTemplateRoleUser.getForObject("/animes/{id}", Anime.class, expectedId);

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }

    // Teste para buscar anime por id com autenticação
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessfulWithAuthenticated() {

       Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

       customUserDetailsRepository.save(ADMIN);
       
       Long expectedId = savedAnime.getId();

       Anime anime = testRestTemplateRoleAdmin.getForObject("/animes/admin/by-id/{id}", Anime.class, expectedId);

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }
    
    // Teste para salvar anime 
    @Test
    @DisplayName("save returns anime when successful")
    void save_ReturnsAnime_whenSuccessful() {

        customUserDetailsRepository.save(ADMIN);

        AnimePostRequestBody animePostRequestBody = AnimePostRequestBodyCreator.createAnimePostRequestBody();

        ResponseEntity<Anime> animeResponseEntity = testRestTemplateRoleAdmin.postForEntity("/animes/admin", animePostRequestBody, Anime.class);

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

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();
    
        ResponseEntity<List<Anime>> response = testRestTemplateRoleUser.exchange("/animes/find/{name}", HttpMethod.GET, null, 
                new ParameterizedTypeReference<List<Anime>>() {}, expectedName);
    
        List<Anime> animes = response.getBody();
    
        Assertions.assertThat(animes).isNotNull().isNotEmpty().hasSize(1);
        Assertions.assertThat(animes.get(0).getName()).isEqualTo(expectedName);
    }    

    // Teste para buscar anime por nome não encontrado 
    @Test
    @DisplayName("findByNome returns an empty list of anime is not found")
    void findByNome_ReturnsEmptyListOfAnime_whenIsNotFound() {

        customUserDetailsRepository.save(USER);

        String url = String.format("/animes/find/dbz");

        ResponseEntity<List<Anime>> response = testRestTemplateRoleUser.exchange(
            url, HttpMethod.GET, null, new ParameterizedTypeReference<List<Anime>>() {}
    );

    // Verificações
    Assertions.assertThat(response.getStatusCodeValue()).isEqualTo(HttpStatus.OK.value());
    Assertions.assertThat(response.getBody()).isNotNull().isEmpty();
    }


    // Teste para atualizar anime 
    @Test
    @DisplayName("replace update anime when successful")
    void replace_UpdatesAnime_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());
        
        customUserDetailsRepository.save(ADMIN);

        savedAnime.setName("Dragon Ball Heroes");

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleAdmin.exchange("/animes/admin", HttpMethod.PUT, new HttpEntity<>(savedAnime), Void.class);

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    // Teste bem sucedido para deletar anime por id testado por um admin
    @Test
    @DisplayName("delete removes anime when successful")
    void delete_RemovesAnime_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(ADMIN);

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleAdmin.exchange("/animes/admin/{id}", HttpMethod.DELETE, null, Void.class, savedAnime.getId());

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

     
    // Teste não sucedido para deletar anime por id testado por um user
    @Test
    @DisplayName("delete removes anime when successful")
    void delete_Returns403_whenUserIsNotAdmin() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleUser.exchange("/animes/admin/{id}", HttpMethod.DELETE, null, Void.class, savedAnime.getId());

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
}