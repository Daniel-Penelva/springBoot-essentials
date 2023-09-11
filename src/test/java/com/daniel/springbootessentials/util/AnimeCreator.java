package com.daniel.springbootessentials.util;

import com.daniel.springbootessentials.domain.Anime;

public class AnimeCreator {

    public static Anime createAnimeToBeSaved(){
        return Anime.builder().name("Hajime in Ippo").build();
    }

    public static Anime createValidAnime(){
        return Anime.builder().id(1L).name("Hajime in Ippo").build();
    }

    public static Anime createValidUpdateAnime(){
        return Anime.builder().id(1L).name("Hajime in Ippo Up").build();
    }
    
}
