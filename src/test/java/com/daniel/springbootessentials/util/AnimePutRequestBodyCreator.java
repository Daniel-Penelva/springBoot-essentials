package com.daniel.springbootessentials.util;

import com.daniel.springbootessentials.requests.AnimePutRequestBody;

public class AnimePutRequestBodyCreator {
 
    public static AnimePutRequestBody createAnimePutRequestBody() {

        return AnimePutRequestBody.builder().name(AnimeCreator.createValidUpdateAnime().getName())
        .id(AnimeCreator.createValidUpdateAnime().getId()).build();
    }
}
