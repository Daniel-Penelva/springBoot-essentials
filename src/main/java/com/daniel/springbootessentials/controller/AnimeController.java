package com.daniel.springbootessentials.controller;

import java.util.List;

import javax.validation.Valid;

import org.springdoc.api.annotations.ParameterObject;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.requests.AnimePutRequestBody;
import com.daniel.springbootessentials.service.AnimeService;

import io.swagger.v3.oas.annotations.Parameter;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("animes")

@AllArgsConstructor // Lombok - Para injeção de dependência (gera construtor)
public class AnimeController {

    private AnimeService animeService;

    // Listar todos os animes: http://localhost:8080/animes
    @GetMapping
    public ResponseEntity<Page<Anime>>  list(@ParameterObject Pageable pageable) {
        return ResponseEntity.ok(animeService.listAll(pageable));
    }

    @GetMapping(path = "/all")
    public ResponseEntity<List<Anime>>  listAll() {
        return ResponseEntity.ok(animeService.listAllNonPageable());
    }

    // Buscar por id o anime: http://localhost:8080/animes/{id}
    @GetMapping(path = "/{id}")
    public ResponseEntity<Anime> findById(@PathVariable("id") Long id) {
        return new ResponseEntity(animeService.findByIdOrThrowBadRequestException(id), HttpStatus.OK);
    }

    // Buscar por id o anime utilizando o @AuthenticationPrincipal UserDetails: http://localhost:8080/animes/by-id/{id}
    //@PreAuthorize("hasRole('ADMIN')")
    @GetMapping(path = "/admin/by-id/{id}")
    public ResponseEntity<Anime> findByIdAuthenticationPrincipal(@PathVariable("id") Long id, @AuthenticationPrincipal UserDetails userDetails) {
        return new ResponseEntity(animeService.findByIdOrThrowBadRequestException(id), HttpStatus.OK);
    }

    // Salvar anime - http://localhost:8080/admin/animes
    //@PreAuthorize("hasRole('ADMIN')")
    @PostMapping(path = "/admin")
    @ResponseBody
    public ResponseEntity<Anime> save(@RequestBody @Valid AnimePostRequestBody animePostRequestBody) {
        return new ResponseEntity<>(animeService.save(animePostRequestBody), HttpStatus.CREATED);
    }

    /* Deletar anime - http://localhost:8080/animes/{id}
    @DeleteMapping(path = "/admin/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        animeService.delete(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
       
         //OBS. HttpStatus.NO_CONTENT - indica que uma solicitação foi processada com
         //sucesso, mas não há conteúdo para retornar na resposta.
         
    }*/

     // Deletar anime - http://localhost:8080/animes/admin/{id}
     // Utilizando o Antmatcher para proteção de URL
    @DeleteMapping(path = "/admin/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        animeService.delete(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    
    }

    // Alterar anime - http://localhost:8080/animes/admin
    @PutMapping(path = "/admin")
    @ResponseBody
    public ResponseEntity<Void> replace(@RequestBody AnimePutRequestBody animePutRequestBody) {
        animeService.replace(animePutRequestBody);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    // Buscar anime por nome: http://localhost:8080/animes/find/{name}
    @GetMapping(path = "/find/{name}")
    public ResponseEntity<List<Anime>> findByName(@PathVariable(value = "name") String name) {
        return ResponseEntity.ok(animeService.findByName(name));
    }

     /* Buscar anime por nome: http://localhost:8080/animes/find?name=Naruto
    @GetMapping(path = "/find")
    public ResponseEntity<List<Anime>> findByName(@RequestParam(name = "name") String name) {
        return ResponseEntity.ok(animeService.findByName(name));
    }*/


}
