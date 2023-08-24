package com.daniel.springbootessentials.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.daniel.springbootessentials.domain.Anime;

public interface AnimeRepository extends JpaRepository<Anime, Long> {

}
