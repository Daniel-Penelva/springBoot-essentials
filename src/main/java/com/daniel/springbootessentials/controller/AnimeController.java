package com.daniel.springbootessentials.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.requests.AnimePutRequestBody;
import com.daniel.springbootessentials.service.AnimeService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("animes")

@AllArgsConstructor // Lombok - Para injeção de dependência (gera construtor)
public class AnimeController {

    private AnimeService animeService;

    // Listar todos os animes: http://localhost:8080/animes
    @GetMapping
    public List<Anime> list() {
        return animeService.listAll();
    }

    // Buscar por id o anime: http://localhost:8080/animes/{id}
    @GetMapping(path = "/{id}")
    public ResponseEntity<Anime> findById(@PathVariable("id") Long id) {
        return new ResponseEntity(animeService.findByIdOrThrowBadRequestException(id), HttpStatus.OK);
    }

    // Salvar anime - http://localhost:8080/animes
    @PostMapping
    @ResponseBody
    public ResponseEntity<Anime> save(@RequestBody AnimePostRequestBody animePostRequestBody) {
        return new ResponseEntity<>(animeService.save(animePostRequestBody), HttpStatus.CREATED);
    }

    // Deletar anime - http://localhost:8080/animes/{id}

    @DeleteMapping(path = "/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        animeService.delete(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);

        /*
         * OBS. HttpStatus.NO_CONTENT - indica que uma solicitação foi processada com
         * sucesso, mas não há conteúdo para retornar na resposta.
         */
    }

    // Alterar anime - http://localhost:8080/animes/
    @PutMapping
    @ResponseBody
    public ResponseEntity<Void> replace(@RequestBody AnimePutRequestBody animePutRequestBody) {
        animeService.replace(animePutRequestBody);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /* Buscar anime por nome: http://localhost:8080/animes/find/{name}
    @GetMapping(path = "/find/{name}")
    public ResponseEntity<List<Anime>> findByName(@PathVariable String name) {
        return ResponseEntity.ok(animeService.findByName(name));
    }*/

     // Buscar anime por nome: http://localhost:8080/animes/find?name=Naruto
    @GetMapping(path = "/find")
    public ResponseEntity<List<Anime>> findByName(@RequestParam(name = "name") String name) {
        return ResponseEntity.ok(animeService.findByName(name));
    }


}
