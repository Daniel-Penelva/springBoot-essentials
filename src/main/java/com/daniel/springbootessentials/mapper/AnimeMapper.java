package com.daniel.springbootessentials.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.requests.AnimePutRequestBody;

@Mapper(componentModel = "spring")
public abstract class AnimeMapper {

    public static final AnimeMapper INSTANCE = Mappers.getMapper(AnimeMapper.class);
    
    public abstract Anime toAnime(AnimePostRequestBody animePostRequestBody);

    public abstract Anime toAnime(AnimePutRequestBody animePutRequestBody);
}
