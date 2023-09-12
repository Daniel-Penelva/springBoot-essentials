package com.daniel.springbootessentials.util;

import com.daniel.springbootessentials.requests.AnimePostRequestBody;

public class AnimePostRequestBodyCreator {

    public static AnimePostRequestBody createAnimePostRequestBody() {

        return AnimePostRequestBody.builder().name(AnimeCreator.createAnimeToBeSaved().getName()).build();
    }
}
