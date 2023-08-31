package com.daniel.springbootessentials.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.daniel.springbootessentials.domain.Anime;

public interface AnimeRepository extends JpaRepository<Anime, Long> {

    List<Anime> findByName(String name);
}
