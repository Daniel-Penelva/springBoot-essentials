package com.daniel.springbootessentials.controller;

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
import com.daniel.springbootessentials.service.AnimeService;
import com.daniel.springbootessentials.util.AnimeCreator;

@ExtendWith(SpringExtension.class)
public class AnimeControllerTest {

    @InjectMocks
    private AnimeController animeController;

    @Mock
    private AnimeService animeService;

    @BeforeEach
    void SetUp(){
      PageImpl<Anime> animePage = new PageImpl<>(List.of(AnimeCreator.createAnimeToBeSaved()));
      BDDMockito.when(animeService.listAll(ArgumentMatchers.any())).thenReturn(animePage);
    }


    @Test
    @DisplayName("List returns list of anime inside page object when successful")
    void list_ReturnsListOfanimesInsidePageObject_whenSuccessful() {

        String expectedName = AnimeCreator.createValidAnime().getName();

        Page<Anime> animePage = animeController.list(null).getBody();

        Assertions.assertThat(animePage).isNotNull();
        Assertions.assertThat(animePage).isNotEmpty().hasSize(1);
        Assertions.assertThat(animePage.toList().get(0).getName()).isEqualTo(expectedName);
    }
}
