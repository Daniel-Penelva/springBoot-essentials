package com.daniel.springbootessentials.repository;

import java.util.List;
import java.util.Optional;

import javax.validation.ConstraintViolationException;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.util.AnimeCreator;

@DataJpaTest
@DisplayName("Tests for Anime Repository")
public class AnimeRepositoryTest {

    @Autowired
    private AnimeRepository animeRepository;

    @Test
    @DisplayName("Save creates anime when Successful")
    void savePersistenceAnimeWhenSuccessful(){
        Anime animeToBeSaved = AnimeCreator.createAnimeToBeSaved();

        Anime animeSaved = this.animeRepository.save(animeToBeSaved);

        Assertions.assertThat(animeSaved).isNotNull();
        Assertions.assertThat(animeSaved.getId()).isNotNull();
        Assertions.assertThat(animeSaved.getName()).isEqualTo(animeToBeSaved.getName());
    }

    @Test
    @DisplayName("Save update anime when Successful")
    void updateAnimeWhenSuccessful(){
        Anime animeToBeSaved = AnimeCreator.createAnimeToBeSaved();

        Anime animeSaved = this.animeRepository.save(animeToBeSaved);
        animeSaved.setName("Overlod");

        Anime animeUpdate = this.animeRepository.save(animeSaved);

        Assertions.assertThat(animeUpdate).isNotNull();
        Assertions.assertThat(animeUpdate.getId()).isNotNull();
        Assertions.assertThat(animeUpdate.getName()).isEqualTo(animeSaved.getName());
    }

    @Test
    @DisplayName("Delete removes anime when Successful")
    void deleteAnimeWhenSuccessful(){
        Anime animeToBeSaved = AnimeCreator.createAnimeToBeSaved();

        Anime animeSaved = this.animeRepository.save(animeToBeSaved);

        this.animeRepository.delete(animeSaved);
        
        Optional<Anime> animeOptional = this.animeRepository.findById(animeSaved.getId());

        Assertions.assertThat(animeOptional.isEmpty());
    }

    @Test
    @DisplayName("Find by name returns list anime when Successful")
    void findByNameAnimeWhenSuccessful(){
        Anime animeToBeSaved = AnimeCreator.createAnimeToBeSaved();

        Anime animeSaved = this.animeRepository.save(animeToBeSaved);

        String anime = animeSaved.getName();

        List<Anime> animes = this.animeRepository.findByName(anime);

        Assertions.assertThat(animes).isNotEmpty();
        Assertions.assertThat(animes).contains(animeSaved);
    }

    @Test
    @DisplayName("Find by name returns empty list when no anime is found")
    void findByName_returnsEmptyList_whenAnimeIsNotFound(){

        List<Anime> animes = this.animeRepository.findByName("outro anime");
        Assertions.assertThat(animes).isEmpty();
    }

    @DisplayName("Save throw ConstraintViolationException_WhenNameIsEmpty")
    @Test
    void save_ThrowsConstraintViolationException_WhenNameIsEmpty(){

        Anime anime = new Anime();

        Assertions.assertThatExceptionOfType(ConstraintViolationException.class)
        .isThrownBy(() -> this.animeRepository.save(anime))
        .withMessageContaining("The anime name cannot be empty");

    }
}
