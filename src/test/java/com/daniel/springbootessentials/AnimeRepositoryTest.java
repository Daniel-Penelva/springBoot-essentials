package com.daniel.springbootessentials;

import java.util.Optional;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.repository.AnimeRepository;

@DataJpaTest
@DisplayName("Tests for Anime Repository")
public class AnimeRepositoryTest {

    @Autowired
    private AnimeRepository animeRepository;

    @Test
    @DisplayName("Save creates anime when Successful")
    void savePersistenceAnimeWhenSuccessful(){
        Anime animeToBeSaved = createAnime();

        Anime animeSaved = this.animeRepository.save(animeToBeSaved);

        Assertions.assertThat(animeSaved).isNotNull();
        Assertions.assertThat(animeSaved.getId()).isNotNull();
        Assertions.assertThat(animeSaved.getName()).isEqualTo(animeToBeSaved.getName());
    }

    @Test
    @DisplayName("Save update anime when Successful")
    void UpdateAnimeWhenSuccessful(){
        Anime animeToBeSaved = createAnime();

        Anime animeSaved = this.animeRepository.save(animeToBeSaved);
        animeSaved.setName("Overlod");

        Anime animeUpdate = this.animeRepository.save(animeSaved);

        Assertions.assertThat(animeUpdate).isNotNull();
        Assertions.assertThat(animeUpdate.getId()).isNotNull();
        Assertions.assertThat(animeUpdate.getName()).isEqualTo(animeSaved.getName());
    }

    @Test
    @DisplayName("Delete removes anime when Successful")
    void DeleteAnimeWhenSuccessful(){
        Anime animeToBeSaved = createAnime();

        Anime animeSaved = this.animeRepository.save(animeToBeSaved);

        this.animeRepository.delete(animeSaved);
        
        Optional<Anime> animeOptional = this.animeRepository.findById(animeSaved.getId());

        Assertions.assertThat(animeOptional.isEmpty());
    }
    
    private Anime createAnime(){
        return Anime.builder().name("Hajime in Ippo").build();
    }
}
