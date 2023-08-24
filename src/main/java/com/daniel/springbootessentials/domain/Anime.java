package com.daniel.springbootessentials.domain;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor 
@NoArgsConstructor
@Entity
public class Anime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    
}

/* OBS. 
 *
 * 1. @AllArgsConstructor: Essa anotação gera um construtor que aceita todos os campos da classe como parâmetros. Em outras palavras, ela cria um 
 * construtor que inicializa todos os campos da classe com base nos argumentos fornecidos. Isso é especialmente útil quando você tem muitos 
 * campos na classe e deseja criar um construtor para inicializá-los rapidamente. A anotação @AllArgsConstructor adiciona um construtor que 
 * aceita todos os campos como parâmetros.
 * 
 * 2. @NoArgsConstructor: Essa anotação gera um construtor sem argumentos, ou seja, um construtor que não aceita parâmetros. Isso é útil quando 
 * você precisa criar instâncias da classe sem fornecer argumentos, por exemplo, quando está usando frameworks que instanciam objetos via 
 * reflexão. Essa anotação cria um construtor vazio que permite a criação de objetos sem inicializar campos.
*/