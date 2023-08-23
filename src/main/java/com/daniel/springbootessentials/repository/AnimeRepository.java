package com.daniel.springbootessentials.repository;

import java.util.List;

import com.daniel.springbootessentials.domain.Anime;

public interface AnimeRepository {

    List<Anime> listAll();
    
}
