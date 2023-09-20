# Guia de estudo Spring Security

## Spring Security

O Spring Security é uma estrutura amplamente utilizada para adicionar segurança a aplicativos baseados em Spring. O filtro `SecurityFilterChain` é um dos componentes cruciais do Spring Security e é usado para configurar as regras de segurança que serão aplicadas a diferentes partes de sua aplicação. O `SecurityFilterChain` é uma configuração composta por vários filtros que definem como a segurança deve ser aplicada em várias partes de sua aplicação.

Alguns conceitos-chave relacionados ao `SecurityFilterChain` no Spring Security:

1. **Security Filter Chain:** É um conjunto de filtros que são executados na ordem especificada para processar solicitações HTTP. Cada filtro executa uma tarefa específica relacionada à segurança, como autenticação, autorização, proteção contra CSRF, entre outros.

2. **Filter Chain Order:** Os filtros no `SecurityFilterChain` são executados em uma ordem específica, determinada pelo número de ordem (ou prioridade) de cada filtro. Isso permite que você controle a sequência exata em que os filtros são aplicados às solicitações.

3. **Filter Chain Entry Points:** Cada `SecurityFilterChain` geralmente começa com um "entry point", que é responsável por decidir como tratar solicitações não autenticadas. Por exemplo, ele pode redirecionar para uma página de login ou retornar um erro não autorizado.

4. **Matcher:** O Spring Security permite que você associe filtros a padrões de URL específicos por meio de matchers. Isso significa que você pode configurar regras de segurança diferentes para URLs diferentes em sua aplicação.

Exemplo simplificado de como pode configurar um `SecurityFilterChain` em uma aplicação Spring Security:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(authorizeRequests ->
                authorizeRequests
                    .antMatchers("/public/**").permitAll()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
            )
            .formLogin(withDefaults());
    }
}
```

Neste exemplo:

- O `SecurityFilterChain` é configurado para permitir acesso não autenticado a URLs que correspondam a `/public/**`, exigir a função "ADMIN" para URLs que correspondam a `/admin/**` e exigir autenticação para todas as outras URLs.
- `formLogin()` é usado para configurar o suporte à autenticação baseada em formulário.

O `SecurityFilterChain` é uma parte essencial da configuração do Spring Security e permite que você defina como as regras de segurança devem ser aplicadas em diferentes partes de sua aplicação. Ele oferece flexibilidade para personalizar a segurança de acordo com as necessidades específicas do seu aplicativo.

## Anotação `@EnableWebSecurity`

A anotação `@EnableWebSecurity` é uma anotação importante e uma parte fundamental da configuração do Spring Security em aplicativos baseados em Spring. Essa anotação é geralmente usada em uma classe de configuração para habilitar o suporte do Spring Security e configurar as políticas de segurança para sua aplicação web.

Alguns pontos-chave sobre a anotação `@EnableWebSecurity`:

1. **Ativação do Spring Security:** Quando anota uma classe de configuração com `@EnableWebSecurity`, você está ativando o suporte do Spring Security para seu aplicativo. Isso faz com que o Spring Security se torne parte do contexto de aplicativo e comece a aplicar as configurações de segurança.

2. **Personalização de Configurações:** A anotação `@EnableWebSecurity` é frequentemente usada em conjunto com uma classe de configuração que estende `WebSecurityConfigurerAdapter`. Isso permite que você personalize as configurações de segurança do Spring Security, como regras de autorização, autenticação, configurações de CORS (Cross-Origin Resource Sharing), proteção CSRF (Cross-Site Request Forgery), entre outros.

3. **Ponto de Início da Configuração:** A classe de configuração anotada com `@EnableWebSecurity` serve como o ponto de entrada para configurar políticas de segurança em seu aplicativo. Ela geralmente inclui métodos anotados com `@Override` que permitem personalizar aspectos específicos da segurança.

Exemplo simples de uso da anotação `@EnableWebSecurity`:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .formLogin().loginPage("/login").permitAll()
            .and()
            .logout().permitAll();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("user").password("{noop}password").roles("USER")
                .and()
                .withUser("admin").password("{noop}admin").roles("ADMIN");
    }
}
```

Neste exemplo, a classe `SecurityConfig` está anotada com `@EnableWebSecurity` e estende `WebSecurityConfigurerAdapter` para personalizar a configuração de segurança. Ela define regras de autorização, configura o suporte à autenticação baseada em formulário e fornece detalhes de autenticação em memória.

Em resumo, a anotação `@EnableWebSecurity` é essencial para ativar e configurar o Spring Security em seu aplicativo web Spring. Ela marca a classe de configuração que será usada para definir as políticas de segurança, como controle de acesso, autenticação e outras configurações relacionadas à segurança.

## Classe `WebSecurityConfigurerAdapter`

A classe `WebSecurityConfigurerAdapter` é uma classe importante no framework Spring Security que fornece uma maneira conveniente de personalizar as configurações de segurança em um aplicativo web Spring. Ela faz parte do módulo Spring Security e é frequentemente estendida para criar classes de configuração personalizadas que definem políticas de segurança específicas para um aplicativo.

Principais pontos sobre a classe `WebSecurityConfigurerAdapter`:

1. **Personalização de Configurações de Segurança:** A classe `WebSecurityConfigurerAdapter` é uma classe base que pode ser estendida para personalizar as configurações de segurança do Spring Security em um aplicativo web. Ela oferece métodos configuráveis que permitem definir políticas de segurança, regras de autorização, autenticação e outras configurações relacionadas à segurança.

2. **Uso de Anotações:** Pode usar anotações Java, como `@Configuration`, `@EnableWebSecurity`, `@EnableGlobalMethodSecurity`, `@Order` e outras, para configurar a classe que estende `WebSecurityConfigurerAdapter`. Essas anotações ajudam a definir quando e como as configurações de segurança personalizadas devem ser aplicadas.

3. **Métodos Configuráveis:** A classe `WebSecurityConfigurerAdapter` possui uma série de métodos configuráveis que podem ser sobrescritos na classe filha para definir comportamentos específicos de segurança. Alguns dos métodos mais comuns incluem:

   - `configure(HttpSecurity http)`: Este método permite configurar as regras de segurança para URLs específicos, como regras de autorização, configurações de CORS, proteção CSRF e muito mais.

   - `configure(AuthenticationManagerBuilder auth)`: Este método permite configurar como a autenticação será realizada, como autenticação em memória, autenticação baseada em banco de dados, autenticação LDAP, etc.

   - `configure(WebSecurity web)`: Este método permite configurar como as solicitações de recursos estáticos (por exemplo, arquivos CSS, JavaScript) são tratadas em relação à segurança.

4. **Prioridade de Configuração:** Quando estende a classe `WebSecurityConfigurerAdapter`, pode criar várias classes de configuração de segurança, cada uma com um propósito diferente. A ordem de prioridade entre essas classes é determinada pelas anotações `@Order` ou pela ordem de carregamento definida pelo Spring. Isso permite que você defina configurações gerais em uma classe e substitua ou adicione configurações específicas em outras classes, se necessário.

5. **Integração com Spring Boot:** Se você estiver usando o Spring Boot, pode simplesmente criar uma classe que estenda `WebSecurityConfigurerAdapter` e, em seguida, personalizar suas configurações de segurança. O Spring Boot fará a configuração automática do Spring Security com base nas configurações que você fornecer.

Em resumo, a classe `WebSecurityConfigurerAdapter` é uma parte crucial do Spring Security que facilita a personalização e configuração das políticas de segurança em um aplicativo web Spring. Ela fornece métodos configuráveis que permitem definir como a autenticação e a autorização devem ser tratadas em seu aplicativo. É amplamente usada para criar configurações de segurança personalizadas em aplicativos Spring Security.

## Classe `PasswordEncoder`

A classe `PasswordEncoder` é uma parte importante do Spring Security que é usada para codificar senhas e validar senhas codificadas em aplicativos web. Ela faz parte do módulo Spring Security e é essencial para a segurança de autenticação em sistemas onde as senhas dos usuários são armazenadas.

A principal função do `PasswordEncoder` é fornecer uma maneira segura de armazenar senhas no banco de dados e verificar se a senha fornecida pelo usuário durante o processo de autenticação corresponde à senha armazenada.

Principais aspectos da classe `PasswordEncoder`:

1. **Codificação de Senhas:** O principal objetivo do `PasswordEncoder` é transformar (codificar) uma senha em uma representação não reversível, conhecida como "hash". Isso é feito para que a senha real não seja armazenada diretamente no banco de dados. O hash é uma sequência de caracteres fixa e única que é gerada a partir da senha original. Quando um usuário tenta fazer login, a senha fornecida é codificada da mesma maneira e o resultado é comparado com o hash armazenado no banco de dados.

2. **Segurança:** O uso de um `PasswordEncoder` é crucial para a segurança de senhas. Ele protege as senhas dos usuários de exposição em caso de violação de dados. Mesmo que um invasor acesse o banco de dados, ele não pode obter as senhas reais, apenas os hashes.

3. **Múltiplos Algoritmos:** O Spring Security oferece várias implementações de `PasswordEncoder`, cada uma usando um algoritmo de hash diferente. Alguns dos algoritmos comuns incluem BCrypt, SCrypt, PBKDF2 e muito mais. A escolha do algoritmo dependerá dos requisitos de segurança do aplicativo. O BCrypt é frequentemente recomendado devido à sua segurança e desempenho.

4. **Configuração:** Em um aplicativo Spring Security, você pode configurar o `PasswordEncoder` para ser usado em sua classe de configuração que estende `WebSecurityConfigurerAdapter`. Isso é feito por meio do método `configure(AuthenticationManagerBuilder auth)`, onde você define como as senhas serão codificadas e verificadas durante o processo de autenticação.

5. **Verificação de Senha:** Além de codificar senhas, o `PasswordEncoder` também fornece métodos para verificar se uma senha não codificada (fornecida pelo usuário durante a autenticação) corresponde ao hash armazenado no banco de dados. O Spring Security cuida dessa verificação automaticamente quando você configura um `PasswordEncoder` apropriado.

Exemplo simples de como usar o `PasswordEncoder` em uma configuração Spring Security:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }
}
```

Neste exemplo, está sendo usando o algoritmo BCrypt para codificar senhas. O método `passwordEncoder()` cria uma instância de `BCryptPasswordEncoder`, que é usada na configuração da autenticação. Quando um usuário tenta fazer login, o Spring Security usará o `BCryptPasswordEncoder` para verificar se a senha fornecida corresponde à senha armazenada no banco de dados.

Classe `PasswordEncoderFactories`

A classe `PasswordEncoderFactories` faz parte do Spring Security e é usada para criar instâncias de `PasswordEncoder` com base em vários algoritmos de codificação de senha. Ela fornece uma maneira fácil de criar um `PasswordEncoder` usando diferentes algoritmos, sem a necessidade de configurá-lo manualmente. A classe `PasswordEncoderFactories` é uma fábrica de `PasswordEncoder`.

Alguns dos métodos estáticos da classe `PasswordEncoderFactories` e os algoritmos de codificação de senha que eles podem criar:

1. **`createDelegatingPasswordEncoder()`**: Este método cria um `PasswordEncoder` que é capaz de verificar senhas codificadas com diferentes algoritmos. Ele suporta senhas codificadas com os seguintes algoritmos:
   - `bcrypt`: Usando o BCryptPasswordEncoder.
   - `noop`: Senhas não codificadas (não recomendado para produção).
   - `sha256`: Usando o StandardPasswordEncoder.
   - `sha256-hex`: Usando o StandardPasswordEncoder com hash em formato hexadecimal.
   - `sha256-b64`: Usando o StandardPasswordEncoder com hash em Base64.

2. **`createDelegatingPasswordEncoder(PasswordEncoder defaultPasswordEncoder, Map<String, PasswordEncoder> idToPasswordEncoder)`**: Este método permite criar um `PasswordEncoder` personalizado com um codificador padrão e um mapa de codificadores adicionais. Isso é útil quando você deseja adicionar suporte a algoritmos de codificação personalizados.

Exemplo de uso:

```java
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Main {
    public static void main(String[] args) {
        // Criar um PasswordEncoder delegado com BCrypt como padrão
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

        // Codificar uma senha usando BCrypt
        String encodedPassword = passwordEncoder.encode("minhaSenha");

        // Verificar se uma senha corresponde ao hash usando o PasswordEncoder
        boolean matches = passwordEncoder.matches("minhaSenha", encodedPassword);
        System.out.println("Senha corresponde: " + matches);
    }
}
```

Neste exemplo, foi usado o `createDelegatingPasswordEncoder()` para criar um `PasswordEncoder` que suporta múltiplos algoritmos, com o BCrypt como padrão. Em seguida, codificamos uma senha usando o BCrypt e verificamos se outra senha corresponde ao hash usando o método `matches()`. O Spring Security cuidará automaticamente da seleção do algoritmo correto com base na senha armazenada no banco de dados.

---

## Classe `SecurityConfig`

```java
package com.daniel.springbootessentials.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.log4j.Log4j2;

@Log4j2
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        log.info("Password enconded {}", passwordEncoder.encode("admin"));

        auth.inMemoryAuthentication()
                .withUser("Daniel")
                .password(passwordEncoder.encode("admin"))
                .roles("USER", "ADMIN")
                .and()
                .withUser("Biana")
                .password(passwordEncoder.encode("admin"))
                .roles("USER");
    }

}
```

Codificação da aplicação Spring Boot usando o Spring Security. Explicando o que cada parte faz:

1. **`@EnableWebSecurity`**: Esta anotação habilita a configuração de segurança da web no aplicativo Spring Boot. Ela é colocada em uma classe de configuração que estende `WebSecurityConfigurerAdapter`.

2. **`WebSecurityConfigurerAdapter`**: Esta é uma classe fornecida pelo Spring Security que permite a configuração da segurança da web. Ao estender essa classe, você pode personalizar as configurações de segurança para sua aplicação.

3. **`configure(HttpSecurity http)`**: Este método permite que você configure a segurança com base nas solicitações HTTP. No exemplo, ele está configurado para exigir autenticação básica (HTTP Basic Authentication) para todas as solicitações (`anyRequest().authenticated()`). Isso significa que todas as solicitações feitas para a aplicação precisam incluir credenciais de autenticação válidas.

4. **`configure(AuthenticationManagerBuilder auth)`**: Este método permite configurar a autenticação. No exemplo, a autenticação é configurada para usar autenticação em memória (in-memory authentication). Isso significa que os detalhes de autenticação (nomes de usuário e senhas) são armazenados em memória e não em um banco de dados externo.

   - `PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();`: Aqui, um `PasswordEncoder` é criado usando `PasswordEncoderFactories`. Este é um codificador de senha que permite usar diferentes algoritmos de codificação de senha.

   - `auth.inMemoryAuthentication()`: Isso indica que está configurando a autenticação em memória.

   - `.withUser("Daniel").password(passwordEncoder.encode("admin")).roles("USER", "ADMIN")`: Isso configura um usuário chamado "Daniel" com a senha "admin" e concede a ele as funções (roles) "USER" e "ADMIN". A senha é codificada antes de ser armazenada usando o `PasswordEncoder`.

   - `.withUser("Biana").password(passwordEncoder.encode("admin")).roles("USER")`: Semelhante ao anterior, configura um usuário chamado "Biana" com a senha "admin" e concede a ele a função (role) "USER".

O código acima configura uma autenticação simples em memória para dois usuários ("Daniel" e "Biana") com senhas codificadas e funções (roles) associadas a eles. Além disso, todas as solicitações precisam passar pela autenticação HTTP básica. Isso é uma configuração básica de segurança, geralmente usada para fins de teste e desenvolvimento. Vale ressaltar que em um ambiente de produção, normalmente configuraria uma autenticação mais robusta, como autenticação baseada em banco de dados ou autenticação OAuth2.

## `CSRF Token no Spring Security`
O Spring Security é uma estrutura popular para segurança em aplicativos Java e oferece suporte robusto para proteger aplicativos da web contra várias ameaças, incluindo ataques CSRF (Cross-Site Request Forgery). No Spring Security, a proteção CSRF é implementada usando um recurso conhecido como "CSRF Token."

Visão geral de como o CSRF Token funciona no Spring Security:

1. **Geração do CSRF Token**:
   - Quando um usuário faz login em um aplicativo protegido pelo Spring Security, um token CSRF é gerado automaticamente pelo framework.
   - Esse token é exclusivo para a sessão do usuário e normalmente é armazenado em uma sessão HTTP ou em um cookie seguro.

2. **Inclusão no Formulário HTML**:
   - O token CSRF gerado é então incluído automaticamente em todos os formulários HTML gerados pelo aplicativo.
   - Isso é feito usando a tag `<input>` especial com o nome `_csrf` (esse nome pode ser personalizado, se necessário).

```html
<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
```

3. **Verificação do CSRF Token**:
   - Quando o usuário envia um formulário ou uma solicitação HTTP que modifica o estado do aplicativo (por exemplo, uma solicitação POST), o Spring Security verifica automaticamente se o token CSRF fornecido na solicitação corresponde ao token armazenado na sessão do usuário.

   - Se os tokens não corresponderem, a solicitação será considerada suspeita e será rejeitada, protegendo assim contra ataques CSRF.

4. **Customização**:
   - O Spring Security permite personalizar várias configurações relacionadas ao CSRF Token, como o nome do parâmetro do token, como o token é armazenado (por exemplo, em um cookie seguro), ou como o token é validado.

Em resumo, o CSRF Token no Spring Security é uma medida fundamental para proteger aplicativos da web contra ataques CSRF, e sua implementação é facilitada pelo framework, permitindo que os desenvolvedores foquem mais em sua lógica de negócios enquanto mantêm a segurança da aplicação.

---

## Alterando o método `configure(HttpSecurity http)` da Classe `SecurityConfig`

```java
package com.daniel.springbootessentials.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.log4j.Log4j2;

@Log4j2
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
 
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) 
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

   ...
}
```

Explicando o que cada parte faz:

1. `http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())`: Esta linha configura a proteção CSRF (Cross-Site Request Forgery) para o aplicativo. Ela diz ao Spring Security para usar o mecanismo CSRF padrão e configura `CookieCsrfTokenRepository` com a opção `withHttpOnlyFalse()`. Isso significa que os tokens CSRF serão armazenados em cookies e podem ser acessados por JavaScript no navegador. O CSRF é uma medida de segurança que evita ataques de falsificação de solicitações entre sites.

2. `.and()`: Este método `and()` é usado para encadear várias configurações juntas.

3. `.authorizeRequests()`: Esta linha inicia a configuração das regras de autorização para solicitações HTTP.

4. `.anyRequest()`: Isso indica que as regras de autorização que se seguem se aplicam a qualquer solicitação.

5. `.authenticated()`: Esta configuração exige que todas as solicitações sejam autenticadas, ou seja, os usuários precisam estar logados para acessar qualquer recurso protegido pelo Spring Security.

6. `.and()`: Mais uma vez, este método `and()` é usado para encadear as configurações.

7. `.httpBasic()`: Esta linha configura a autenticação básica HTTP. Isso significa que, quando um usuário tentar acessar um recurso protegido, o navegador solicitará um nome de usuário e senha.

Resumidamente, o script acima configura um aplicativo Spring Security para exigir autenticação básica (HTTP Basic Authentication) para todas as solicitações e protege contra ataques CSRF, armazenando os tokens CSRF em cookies acessíveis por JavaScript no navegador. Isso é uma configuração básica e pode ser personalizada de acordo com os requisitos específicos de segurança do aplicativo.

## Anotação `@PreAuthorize` do Spring Security

**`@PreAuthorize`** é uma anotação de segurança oferecida pelo Spring Security que permite a você definir expressões de autorização em métodos de seus controladores ou serviços Spring. Essas expressões determinam se um usuário tem permissão para acessar ou executar um método específico com base em critérios definidos por você.

Explicação mais detalhada de como a anotação `@PreAuthorize` funciona:

1. **Expressões de Autorização**:
   - A anotação `@PreAuthorize` aceita uma expressão de autorização como seu valor.
   - Essa expressão é avaliada pelo Spring Security antes de executar o método associado à anotação.
   - A expressão pode ser uma combinação de operadores lógicos, funções e informações do usuário para determinar se a solicitação deve ser permitida.

2. **Informações do Usuário**:
   - Você pode usar informações sobre o usuário atual na expressão de autorização, como seu nome de usuário, funções (roles), atributos personalizados, entre outros.
   - Exemplos de informações do usuário que você pode acessar na expressão incluem: `#authentication`, `#principal`, `#username`, `#hasRole('ROLE_ADMIN')`, entre outros.

3. **Exemplos de Expressões**:
   - Alguns exemplos de expressões de autorização:
     - `@PreAuthorize("hasRole('ROLE_ADMIN')")`: Requer que o usuário tenha a função (role) "ROLE_ADMIN".
     - `@PreAuthorize("hasIpAddress('192.168.0.1')")`: Permite apenas solicitações de um endereço IP específico.
     - `@PreAuthorize("isAuthenticated()")`: Requer que o usuário esteja autenticado.
     - `@PreAuthorize("#username == 'daniel'")`: Permite apenas se o nome de usuário for "daniel".

4. **Operadores Lógicos**:
   - Você pode usar operadores lógicos, como `and`, `or` e `not`, para criar condições de autorização mais complexas.
   - Por exemplo, `@PreAuthorize("hasRole('ROLE_ADMIN') and hasIpAddress('192.168.0.1')")` requer que o usuário seja um administrador e esteja acessando de um endereço IP específico.

5. **Uso em Controladores e Serviços**:
   - A anotação `@PreAuthorize` pode ser usada em métodos de classes de controladores (annotated com `@Controller`) e serviços (annotated com `@Service`).
   - Ela permite definir regras de autorização específicas para cada método, adaptadas às necessidades do aplicativo.

6. **Configuração do Spring Security**:
   - Para que as expressões de autorização definidas com `@PreAuthorize` funcionem corretamente, você precisa configurar o Spring Security em seu aplicativo e configurar regras de segurança adequadas, como definição de funções e configuração de autenticação.

Em resumo, a anotação `@PreAuthorize` é uma maneira poderosa e flexível de adicionar camadas de segurança granulares em métodos específicos de seus componentes Spring. Ela permite que você controle o acesso com base em critérios personalizados, aproveitando informações do usuário e expressões de autorização flexíveis. Isso ajuda a garantir que apenas usuários autorizados tenham acesso a recursos específicos em seu aplicativo.

## Anotação `@EnableGlobalMethodSecurity` do Spring Security

A anotação `@EnableGlobalMethodSecurity` é usada em configurações do Spring Security para habilitar o suporte a segurança em nível de método. Quando você a usa com a opção `prePostEnabled = true`, permite o uso de anotações de segurança, como `@PreAuthorize` e `@PostAuthorize`, para controlar o acesso a métodos específicos em seu aplicativo.

Aqui estão os detalhes dessa anotação:

- `@EnableGlobalMethodSecurity` é uma anotação de configuração do Spring Security.
- `prePostEnabled = true` é um parâmetro da anotação que, quando definido como `true`, habilita o uso de anotações de segurança baseadas em expressões, como `@PreAuthorize` e `@PostAuthorize`, em seus métodos.

Como isso funciona:

1. **Habilitar a Segurança em Nível de Método**:
   - Quando você adiciona a anotação `@EnableGlobalMethodSecurity(prePostEnabled = true)` à sua configuração do Spring Security, você está ativando o suporte a segurança em nível de método em seu aplicativo.

2. **Uso de Anotações de Segurança**:
   - Com o suporte a segurança em nível de método habilitado, você pode usar anotações de segurança, como `@PreAuthorize` e `@PostAuthorize`, em métodos de seus controladores ou serviços.
   - Essas anotações permitem que você defina regras de autorização personalizadas para métodos específicos com base em expressões.

Em resumo, a anotação `@EnableGlobalMethodSecurity(prePostEnabled = true)` é usada para habilitar o suporte a segurança em nível de método no Spring Security, permitindo o uso de anotações de segurança como `@PreAuthorize` e `@PostAuthorize` para controlar o acesso a métodos específicos com base em regras de autorização personalizadas. Isso é útil quando você precisa de granularidade nas permissões dentro de seu aplicativo, permitindo que diferentes métodos tenham diferentes requisitos de autorização.

---

## Alterando o método `save(...)` da Classe `AnimeController` e desabilitando o CSRF TOKEN

```java
package com.daniel.springbootessentials.controller;

imports...

@RestController
@RequestMapping("animes")
@AllArgsConstructor // Lombok - Para injeção de dependência (gera construtor)
public class AnimeController {

    private AnimeService animeService;

    ...

    // Salvar anime - http://localhost:8080/animes
    @PostMapping
    @ResponseBody
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Anime> save(@RequestBody @Valid AnimePostRequestBody animePostRequestBody) {
        return new ResponseEntity<>(animeService.save(animePostRequestBody), HttpStatus.CREATED);
    }

    ...
}
```

No exemplo acima, o método `save` só pode ser executado por usuários que têm a função (role) "ADMIN". Isso é possível graças ao uso da anotação @PreAuthorize, que é habilitada pela configuração @EnableGlobalMethodSecurity(prePostEnabled = true) mostrado na imagem abaixo.

```java
package com.daniel.springbootessentials.config;

imports...

@Log4j2
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
//              .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        log.info("Password enconded {}", passwordEncoder.encode("admin"));

        auth.inMemoryAuthentication()
                .withUser("Daniel")
                .password(passwordEncoder.encode("admin"))
                .roles("USER", "ADMIN")
                .and()
                .withUser("Biana")
                .password(passwordEncoder.encode("admin"))
                .roles("USER");
    }

}
```

A configuração de autenticação, somente quem tem a função Role "ADMIN" poderá executar a requisição do método 
HTTP POST, ou seja, para o usuário "Daniel" a sua função definida "ADMIN" permitirá executar tal requisição, ao contrário do usuário "Biana" que a sua função definida é de apenas de usuário (USER), logo ela não está autorizada a utilizar o método HTTP POST para criação de anime.

## Anotação `@AuthenticationPrincipal`

A anotação `@AuthenticationPrincipal` é uma anotação do Spring Security que facilita o acesso ao objeto `Principal` (representando o usuário autenticado) em seus controladores ou serviços Spring. Essa anotação é especialmente útil quando você precisa acessar informações específicas do usuário autenticado em um método de controlador ou serviço.

Detalhes dessa anotação:

1. **Objeto `Principal`**:
   - O objeto `Principal` é uma parte fundamental do sistema de autenticação do Spring Security. Ele representa o usuário autenticado na sessão atual.

2. **Uso do `@AuthenticationPrincipal`**:
   - A anotação `@AuthenticationPrincipal` permite injetar diretamente o objeto `Principal` no método de um controlador ou serviço Spring.
   - Ela simplifica o acesso às informações do usuário autenticado, tornando-as facilmente disponíveis como um parâmetro do método.

Essa anotação é útil quando você precisa acessar informações específicas do usuário autenticado em seus métodos de controlador ou serviço, tornando o código mais limpo e legível.

Além disso, observe que a anotação `@AuthenticationPrincipal` também pode ser usada com classes personalizadas em vez de `Principal`. Por exemplo, se você tiver uma classe `User` representando os detalhes do usuário autenticado, você pode usá-la em vez de `Principal`, desde que a classe implemente a interface `Principal`.

---

## Criando o método `findByIdAuthenticationPrincipal` na Classe `AnimeController`

```java
package com.daniel.springbootessentials.controller;

imports ...

@RestController
@RequestMapping("animes")

@AllArgsConstructor // Lombok - Para injeção de dependência (gera construtor)
public class AnimeController {

    private AnimeService animeService;

   ...

 // Buscar por id o anime utilizando o @AuthenticationPrincipal UserDetails: http://localhost:8080/animes/by-id/{id}
    @GetMapping(path = "by-id/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Anime> findByIdAuthenticationPrincipal(@PathVariable("id") Long id, @AuthenticationPrincipal UserDetails userDetails) {
        return new ResponseEntity(animeService.findByIdOrThrowBadRequestException(id), HttpStatus.OK);
    }

    ...
}
```

O código acima é um endpoint de controle em um aplicativo Spring que usa o Spring Security para garantir que apenas os usuários com a função (role) "ADMIN" possam acessá-lo. 

Explicando o que cada parte faz:

1. **`@GetMapping(path = "by-id/{id}")`**: Esta anotação marca o método como um manipulador de solicitação HTTP GET. Ele especifica que este método será invocado quando uma solicitação GET for feita para a URL relativa `/animes/by-id/{id}`, onde `{id}` é um valor de variável de caminho (path variable) que pode ser fornecido na URL.

2. **`@PreAuthorize("hasRole('ADMIN')")`**: Esta anotação é parte do mecanismo de autorização do Spring Security. Ela define uma expressão SpEL (Spring Expression Language) que especifica a regra de autorização para este método. A expressão `hasRole('ADMIN')` verifica se o usuário autenticado possui a função (role) "ADMIN". Apenas os usuários com essa função terão acesso a este método. Caso contrário, uma exceção de acesso não autorizado será lançada.

3. **`@PathVariable("id") Long id`**: Isso marca o parâmetro `id` como uma variável de caminho (path variable) na URL. O valor do `{id}` na URL será atribuído a este parâmetro.

4. **`@AuthenticationPrincipal UserDetails userDetails`**: Esta anotação permite injetar o objeto `UserDetails` do usuário autenticado no método. Isso é útil se você precisar acessar informações sobre o usuário autenticado dentro do método.

5. **`return new ResponseEntity(animeService.findByIdOrThrowBadRequestException(id), HttpStatus.OK);`**: Este é o corpo do método. Ele chama um serviço chamado `animeService` para buscar um anime por ID usando o método `findByIdOrThrowBadRequestException(id)`. Se o anime for encontrado, ele é encapsulado em uma instância de `ResponseEntity` com um status HTTP 200 (OK) e retornado como resposta.

No geral, este endpoint de controle é protegido pelo Spring Security com a anotação `@PreAuthorize`, que garante que apenas os usuários com a função "ADMIN" possam acessá-lo. Além disso, ele usa o `@AuthenticationPrincipal` para acessar informações sobre o usuário autenticado, se necessário, e retorna um anime específico com base no ID fornecido na URL. Esse é um exemplo típico de como usar o Spring Security para controlar o acesso a recursos protegidos em um aplicativo Spring.

## Interface `UserDetails`

A Interface `UserDetails` faz parte do Spring Security e é uma parte fundamental do sistema de autenticação e autorização. Ela é uma interface que define um contrato para fornecer informações sobre um usuário autenticado no sistema. Implementar a interface `UserDetails` permite personalizar a forma como o Spring Security lida com os detalhes do usuário durante a autenticação e a autorização.

Principais componentes da interface `UserDetails` e como ela é usada:

1. **getUsername()**: Este método retorna o nome de usuário associado ao objeto UserDetails. O nome de usuário é usado para autenticar o usuário durante o processo de login. Ele é geralmente uma string única que identifica exclusivamente um usuário no sistema. 

2. **getPassword()**: Retorna a senha do usuário. A senha geralmente está criptografada para segurança. Durante o processo de autenticação, o Spring Security compara a senha fornecida pelo usuário com a senha armazenada no `UserDetails`.

3. **getAuthorities()**: Retorna uma coleção de autoridades (papéis ou funções) associadas ao usuário. As autoridades representam as permissões do usuário e são usadas pelo Spring Security para controle de acesso. Uma autoridade pode ser algo como "ROLE_USER" ou "ROLE_ADMIN".

4. **isAccountNonExpired()**: Este método indica se a conta do usuário está ou não expirada. Se a conta estiver expirada, o usuário não poderá efetuar login.

5. **isAccountNonLocked()**: Verifica se a conta do usuário está bloqueada ou não. Se a conta estiver bloqueada, o usuário não poderá efetuar login.

6. **isCredentialsNonExpired()**: Verifica se as credenciais do usuário, geralmente a senha, estão ou não expiradas. Se as credenciais estiverem expiradas, o usuário não poderá efetuar login.

7. **isEnabled()**: Indica se a conta do usuário está habilitada ou não. Se a conta estiver desabilitada, o usuário não poderá efetuar login.

A classe `UserDetails` é uma interface e pode ser implementada de várias maneiras, dependendo das necessidades do seu aplicativo. Além disso, o Spring Security fornece uma implementação padrão chamada `User`, que implementa a interface `UserDetails` e é frequentemente usada para armazenar informações de usuário durante o processo de autenticação e autorização.

Em resumo, a classe `UserDetails` é uma interface do Spring Security que define um contrato para fornecer informações sobre um usuário autenticado, incluindo nome de usuário, senha, autoridades e status de conta. Implementar essa interface permite personalizar como o Spring Security lida com os detalhes do usuário em seu aplicativo.

## Criando a Classe `CustomUserDetails` implementando a Interface `UserDetails`

```java
package com.daniel.springbootessentials.domain;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Builder
public class CustomUserDetails implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotEmpty(message = "The anime name cannot be empty")
    @NotNull(message = "The anime name cannot be null")
    @NotBlank
    private String name;

    private String username;
    private String password;
    private String authorities; // ROLE_ADMIN, ROLE_USER

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return Arrays.stream(authorities.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {

        return this.password;
    }

    @Override
    public String getUsername() {

        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```
--- 

## Criando a Interface `CustomUserDetailsRepository`

```java
package com.daniel.springbootessentials.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.daniel.springbootessentials.domain.CustomUserDetails;

public interface CustomUserDetailsRepository extends JpaRepository<CustomUserDetails, Long> {

    CustomUserDetails findByUsername(String username);
}
```

Essa interface é usada para interagir com dados relacionados a CustomUserDetails em um banco de dados usando o Spring Data JPA, como buscar um usuário por nome de usuário. 

## Interface `UserDetailsService`

A interface `UserDetailsService` é uma parte fundamental do Spring Security e é usada para carregar detalhes de usuário durante o processo de autenticação. Ela define um contrato que deve ser implementado para recuperar informações de usuário com base no nome de usuário (username). 

Detalhes dessa interface:

1. **`loadUserByUsername(String username)`**: Este é o único método da interface `UserDetailsService` que deve ser implementado. Ele recebe o nome de usuário como argumento e retorna um objeto que implementa a interface `UserDetails`.

   - `String username`: O nome de usuário que está sendo usado para autenticar o usuário.
   - Retorna um objeto `UserDetails` que representa os detalhes do usuário, incluindo informações como nome de usuário, senha, autoridades (funções ou papéis), e estados de conta, como se a conta está habilitada, bloqueada, etc.

Geralmente, ao implementar a interface `UserDetailsService`, você se conectará a uma fonte de dados, como um banco de dados, para buscar os detalhes do usuário com base no nome de usuário fornecido. Em seguida, você retornará esses detalhes como um objeto que implementa a interface `UserDetails`.

A implementação da interface `UserDetailsService` é uma parte fundamental da configuração do Spring Security e permite que o sistema autentique os usuários com base nas informações armazenadas em uma fonte de dados. Ela permite a personalização do processo de carregamento de detalhes do usuário para atender às necessidades específicas do seu aplicativo.

--- 

## Criando a Classe `CustomUserDetailsService` implementando a Interface `UserDetailsService`

```java
package com.daniel.springbootessentials.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.daniel.springbootessentials.repository.CustomUserDetailsRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final CustomUserDetailsRepository customUserDetailsRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return Optional.ofNullable(customUserDetailsRepository.findByUsername(username))
                .orElseThrow(() -> new UsernameNotFoundException("Custom user details not found"));
    }
}
```

Essa classe implementa a interface `UserDetailsService` do Spring Security e é responsável por carregar detalhes de usuário com base no nome de usuário durante o processo de autenticação. Vou explicar os principais aspectos desse script:

Explicando o que cada parte faz:

1. **`@Service`**: Esta anotação marca a classe como um componente de serviço gerenciado pelo Spring. Isso significa que você pode injetá-la em outras partes do seu aplicativo Spring.

2. **`@RequiredArgsConstructor`**: Esta anotação é usada para gerar automaticamente um construtor que aceita todos os campos marcados como `final`. No seu caso, ele está sendo usado para injetar automaticamente o `CustomUserDetailsRepository` no serviço.

3. **`private final CustomUserDetailsRepository customUserDetailsRepository;`**: Aqui, você declara uma instância do `CustomUserDetailsRepository` como um campo final. Isso permite que o Spring injete automaticamente uma instância do repositório no serviço quando o serviço é criado.

4. **`return Optional.ofNullable(customUserDetailsRepository.findByUsername(username))`**: Aqui, a classe `CustomUserDetailsRepository` é usada para buscar um objeto `CustomUserDetails` com base no nome de usuário fornecido. A utilização de `Optional.ofNullable` lida com a possibilidade de o usuário não ser encontrado no banco de dados.

8. **`.orElseThrow(() -> new UsernameNotFoundException("Custom user details not found"));`**: Este trecho de código é usado para lançar uma exceção `UsernameNotFoundException` caso o usuário não seja encontrado no banco de dados. Essa exceção é usada para sinalizar que o nome de usuário não existe e pode ser tratada adequadamente no processo de autenticação.

Em resumo, essa classe `CustomUserDetailsService` é responsável por carregar os detalhes do usuário com base no nome de usuário fornecido durante o processo de autenticação. Ela usa o `CustomUserDetailsRepository` para buscar os detalhes do usuário no banco de dados e, se o usuário não for encontrado, lança uma exceção `UsernameNotFoundException`. Isso é uma parte importante do mecanismo de autenticação do Spring Security, permitindo que o sistema autentique os usuários com base nas informações armazenadas no banco de dados.


## Proteção de URL com `antMatchers()`
A proteção de URL com `antMatchers()` é uma parte essencial da configuração de segurança do Spring Security. O método `antMatchers()` permite especificar padrões de URL e aplicar regras de segurança específicas a essas URLs. Isso é útil para definir quais URLs estão protegidas e quais regras de autorização se aplicam a elas. Aqui está uma explicação mais detalhada:

1. **`antMatchers(String... antPatterns)`**: O método `antMatchers()` é usado para definir padrões de URL que você deseja proteger ou aplicar regras de segurança. Você pode fornecer um ou mais padrões de URL como argumentos para este método. Um padrão de URL é uma string que pode conter wildcards, como `*` e `**`, para corresponder a várias URLs.

2. **Regras de Autorização**:
   - Após chamar `antMatchers()`, você pode encadear métodos para definir regras de autorização específicas para esses padrões de URL. Alguns dos métodos comuns incluem:
     - `.permitAll()`: Permite que todas as solicitações correspondentes acessem a URL sem autenticação.
     - `.authenticated()`: Exige que os usuários estejam autenticados para acessar a URL.
     - `.hasRole("ROLE_NAME")`: Exige que os usuários tenham uma função específica para acessar a URL.
     - `.hasAnyRole("ROLE1", "ROLE2")`: Exige que os usuários tenham pelo menos uma das funções especificadas para acessar a URL.
     - `.hasAuthority("AUTHORITY_NAME")`: Exige que os usuários tenham uma autoridade específica para acessar a URL.
     - `.hasAnyAuthority("AUTH1", "AUTH2")`: Exige que os usuários tenham pelo menos uma das autoridades especificadas para acessar a URL.
     - `.hasIpAddress("IP_ADDRESS")`: Exige que as solicitações originem de um endereço IP específico.

3. **Exemplo de Uso**:
   - Vejamos um exemplo de uso do `antMatchers()` em uma classe de configuração do Spring Security:

   ```java
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       http
           .authorizeRequests()
               .antMatchers("/public/**").permitAll() // URLs públicas acessíveis por todos
               .antMatchers("/admin/**").hasRole("ADMIN") // URLs restritas ao papel ADMIN
               .anyRequest().authenticated() // Todas as outras URLs exigem autenticação
           .and()
           .formLogin() // Configuração de formulário de login
               .loginPage("/login") // Página de login personalizada
               .permitAll()
           .and()
           .logout()
               .permitAll();
   }
   ```

Neste exemplo:

- URLs que correspondem a `/public/**` são acessíveis por todos sem autenticação.
- URLs que correspondem a `/admin/**` exigem que os usuários tenham a função "ADMIN" para acessá-las.
- Todas as outras URLs exigem autenticação.
- Além disso, a configuração inclui a página de login personalizada e configurações relacionadas ao logout.

O uso de `antMatchers()` permite uma configuração granular e flexível da segurança com base em padrões de URL. Isso é especialmente útil em aplicativos complexos com várias URLs e requisitos de segurança diferentes para cada uma delas.

---

## Alternado o método `configure(HttpSecurity http)` da Classe `SecurityConfig` 

```java
package com.daniel.springbootessentials.config;

imports ...

@Log4j2
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    
        http.csrf().disable()
                // .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .authorizeRequests()
                .antMatchers("/animes/admin/**").hasRole("ADMIN")
                .antMatchers("/animes/**").hasAnyRole("ADMIN", "USER")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();
    }

    ...
}
```

Explicando o que cada parte faz:

1. **`http.csrf().disable()`**: Isso desativa a proteção CSRF (Cross-Site Request Forgery) para o aplicativo. A proteção CSRF é uma medida de segurança que protege contra ataques em que um atacante engana o usuário para realizar ações não intencionadas em um site.

2. **`authorizeRequests()`**: Isso inicia a configuração das regras de autorização para solicitações HTTP.

3. **`.antMatchers("/animes/admin/**").hasRole("ADMIN")`**: Esta linha especifica uma regra de autorização que permite que os usuários com a função (role) "ADMIN" acessem URLs que correspondam ao padrão "/animes/admin/**". Isso significa que apenas os usuários com a função "ADMIN" podem acessar URLs que começam com "/animes/admin/".

4. **`.antMatchers("/animes/**").hasAnyRole("ADMIN", "USER")`**: Esta linha especifica outra regra de autorização que permite que os usuários com as funções "ADMIN" ou "USER" acessem URLs que correspondam ao padrão "/animes/**". Isso significa que tanto os usuários com a função "ADMIN" quanto os usuários com a função "USER" podem acessar URLs que começam com "/animes/".

5. **`.anyRequest().authenticated()`**: Esta linha define que qualquer outra solicitação (aquelas que não correspondem às regras anteriores) requer autenticação. Isso significa que todas as outras solicitações precisam ser realizadas por um usuário autenticado.

6. **`.formLogin()`**: Isso configura o suporte para login baseado em formulário. Isso permite que os usuários forneçam credenciais de autenticação por meio de um formulário da web.

7. **`.httpBasic()`**: Isso também configura a autenticação básica do HTTP. Com isso habilitado, os usuários podem fornecer credenciais de autenticação por meio de pop-ups de autenticação do navegador.

No geral, este método `configure(HttpSecurity http)` está configurando as regras de autorização do aplicativo. Ele permite que os usuários com a função "ADMIN" acessem URLs específicas relacionadas a administração de animes, enquanto permite que os usuários com as funções "ADMIN" ou "USER" acessem outras URLs relacionadas aos animes. Qualquer outra solicitação não permitida pelas regras anteriores exige autenticação. Isso é uma configuração comum para aplicativos web que possuem áreas públicas e áreas restritas para diferentes tipos de usuários.

---

## Alternado as URLs dos métodos HTTP da Classe `AnimeController`

```java
package com.daniel.springbootessentials.controller;

import java.util.List;

import javax.validation.Valid;

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

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("animes")

@AllArgsConstructor // Lombok - Para injeção de dependência (gera construtor)
public class AnimeController {

    private AnimeService animeService;

    // Listar todos os animes: http://localhost:8080/animes
    @GetMapping
    public ResponseEntity<Page<Anime>>  list(Pageable pageable) {
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
}
```
## Anotação `@TestConfiguration`

A anotação `@TestConfiguration` é uma anotação usada em testes de unidade e testes de integração em aplicativos Spring. Ela faz parte do ecossistema Spring Framework e é usada para definir configurações específicas para testes que substituem ou complementam as configurações padrão do aplicativo durante a execução dos testes. 

Pontos importantes sobre a anotação `@TestConfiguration`:

1. **Contexto de Teste Isolado**: Quando executa testes em um aplicativo Spring, é importante manter um ambiente de teste isolado que não afete o ambiente de produção. O `@TestConfiguration` permite configurar beans específicos para testes sem afetar a configuração real do aplicativo.

2. **Substituição de Configurações**: Você pode usar `@TestConfiguration` para substituir ou complementar configurações existentes do Spring, como beans de serviço ou configurações de banco de dados, para criar cenários específicos de teste.

3. **Escopo de Teste**: As classes anotadas com `@TestConfiguration` são consideradas parte do contexto de teste e, portanto, têm um escopo de vida limitado ao escopo de teste em que estão sendo usadas. Isso significa que essas configurações só são aplicadas durante a execução dos testes em que a classe `@TestConfiguration` é utilizada.

4. **Flexibilidade de Configuração**: O uso de `@TestConfiguration` oferece flexibilidade na configuração de dependências específicas para testes, como fontes de dados simuladas, serviços simulados ou qualquer outra configuração necessária para criar cenários de teste controlados.

Em resumo, `@TestConfiguration` é uma anotação poderosa que ajuda a configurar o ambiente de teste de forma flexível e controlada, permitindo a substituição de beans e configurações específicas para testes de unidade e testes de integração em aplicativos Spring. Isso contribui para a criação de testes mais isolados e confiáveis.

## Classe `RestTemplateBuilder`

A classe `RestTemplateBuilder` faz parte do ecossistema Spring Framework e é usada para criar e configurar instâncias da classe `RestTemplate`, que é uma classe fornecida pelo Spring Framework para fazer chamadas HTTP a serviços web RESTful. O `RestTemplate` permite realizar solicitações HTTP GET, POST, PUT, DELETE e outras operações com facilidade.

O `RestTemplateBuilder` é uma ferramenta útil para configurar instâncias personalizadas do `RestTemplate` com várias opções de configuração. Ele fornece um estilo de construção (builder) para criar e personalizar instâncias do `RestTemplate` de acordo com suas necessidades específicas.

Principais funcionalidades e usos comuns da classe `RestTemplateBuilder`:

1. **Configuração de Propriedades**: Você pode usar o `RestTemplateBuilder` para configurar várias propriedades do `RestTemplate`, como timeouts, interceptadores, conversores de mensagem e outros.

2. **Configuração de Autenticação**: É possível configurar autenticação, como autenticação básica (HTTP Basic Authentication) ou autenticação baseada em token, usando o `RestTemplateBuilder`.

3. **Customização de Conversores de Mensagem**: O `RestTemplateBuilder` permite personalizar os conversores de mensagem usados pelo `RestTemplate`, o que é útil quando você precisa lidar com formatos de mensagem específicos, como JSON ou XML.

4. **Personalização de Interceptors**: Você pode adicionar interceptadores personalizados para manipular solicitações e respostas HTTP antes ou depois de serem enviadas e recebidas pelo `RestTemplate`.

5. **Timeouts**: É possível definir timeouts para solicitações HTTP, controlando quanto tempo o `RestTemplate` aguardará por uma resposta antes de considerá-la como falha.

6. **Pool de Conexões**: O `RestTemplateBuilder` permite configurar o pool de conexões HTTP subjacente usado pelo `RestTemplate`, o que pode melhorar o desempenho em cenários de alta concorrência.

7. **Configuração de Proxy**: Você pode configurar um proxy HTTP para as solicitações feitas pelo `RestTemplate` usando o `RestTemplateBuilder`.

Em resumo, o `RestTemplateBuilder` é uma ferramenta poderosa para criar e configurar instâncias personalizadas do `RestTemplate` em aplicativos Spring, facilitando a integração com serviços web RESTful de forma flexível e controlada. Ele permite que você defina várias opções de configuração para atender às necessidades específicas de suas chamadas HTTP.

## Anotação `@Bean`

A anotação `@Bean` é uma anotação do Spring Framework e é amplamente usada na configuração de contêineres de inversão de controle (IoC) e injeção de dependência. Ela é usada para indicar ao Spring que um método em uma classe de configuração (geralmente anotada com `@Configuration`) deve ser tratado como um método de fábrica para criar um bean gerenciado pelo Spring. 

Principais pontos a serem observados sobre a anotação `@Bean`:

1. **Definição de Bean Gerenciado**: Quando você anota um método com `@Bean`, você está dizendo ao Spring que o método deve ser usado para criar um objeto que será gerenciado pelo contêiner de IoC do Spring.

2. **Método de Fábrica**: O método anotado com `@Bean` age como um método de fábrica que cria e configura o bean. O Spring chamará esse método para obter uma instância do bean sempre que for necessário.

3. **Configuração Personalizada**: O método anotado com `@Bean` pode conter código para configurar e personalizar o bean, incluindo a definição de propriedades, a configuração de dependências e qualquer inicialização necessária.

4. **Injeção de Dependência**: Os beans criados com `@Bean` podem ser injetados em outros beans usando injeção de dependência, permitindo a criação de gráficos complexos de objetos gerenciados pelo Spring.

5. **Escopo do Bean**: O escopo do bean criado com `@Bean` pode ser configurado usando outras anotações, como `@Scope`. Isso permite que você especifique se o bean é singleton, protótipo, sessão, etc.

6. **Benefícios**: A anotação `@Bean` permite que você crie beans gerenciados pelo Spring de forma declarativa e flexível. Isso promove a modularidade, a reutilização de código e a separação de preocupações em seu aplicativo.

Em resumo, a anotação `@Bean` é usada para definir métodos de fábrica para criar beans gerenciados pelo Spring. Ela desempenha um papel fundamental na configuração e personalização de beans em aplicativos Spring e é uma parte essencial do modelo de injeção de dependência do Spring.

## anotação `@Qualifier`

A anotação `@Qualifier` é usada em conjunto com a injeção de dependência no Spring Framework para especificar qual bean específico deve ser injetado quando existem várias implementações ou instâncias de uma mesma interface ou classe disponíveis no contexto do Spring. Ela é usada para resolver ambiguidades de injeção quando o Spring não consegue determinar qual bean deve ser injetado com base apenas no tipo da dependência.

Aqui estão os principais pontos a serem observados sobre a anotação `@Qualifier`:

1. **Resolução de Ambiguidade**: Em situações em que existem múltiplas implementações ou instâncias de um mesmo tipo (por exemplo, várias implementações de uma mesma interface), o Spring pode ficar em dúvida sobre qual bean injetar. O `@Qualifier` permite especificar explicitamente o nome ou valor do bean que você deseja injetar.

2. **Valor do `@Qualifier`**: O valor do `@Qualifier` é uma string que corresponde ao nome do bean que você deseja injetar. Você deve fornecer o nome exato do bean que está definido no contexto do Spring.

3. **Outras Alternativas**: Além do `@Qualifier`, o Spring oferece outras formas de resolver ambiguidades de injeção, como a anotação `@Primary` (que define o bean preferencial a ser injetado quando há ambiguidade) e a anotação `@Resource` (que pode ser usada com o atributo `name` para especificar o nome do bean a ser injetado).

5. **Personalização de Beans**: A combinação do `@Qualifier` com a anotação `@Service` (ou outras anotações de componentes) permite que você personalize os nomes dos beans, tornando mais fácil a resolução de ambiguidades por nome.

O `@Qualifier` é uma ferramenta útil para situações em que você precisa especificar explicitamente qual implementação de um tipo deve ser injetada. Ele oferece flexibilidade e controle sobre a injeção de dependência em aplicativos Spring com configurações complexas de beans.

## Anotação `@Lazy`

A anotação `@Lazy` é uma anotação do Spring Framework que pode ser aplicada a componentes gerenciados pelo Spring, como beans. Ela modifica o comportamento padrão de inicialização desses componentes, tornando-os preguiçosos (lazy) em vez de serem inicializados imediatamente durante a inicialização do aplicativo. Isso significa que o bean só será criado quando for acessado pela primeira vez.

Principais pontos a serem observados sobre a anotação `@Lazy`:

1. **Inicialização Preguiçosa**: Quando um bean é marcado com `@Lazy`, ele não será inicializado imediatamente quando o contexto do Spring for criado. Em vez disso, a inicialização do bean é adiada até que ele seja solicitado pela primeira vez em algum lugar do código.

2. **Economia de Recursos**: O uso de `@Lazy` pode economizar recursos, especialmente se você tiver muitos beans e nem todos eles forem necessários no início da execução do aplicativo. Isso evita a criação desnecessária de beans e pode melhorar o desempenho e a eficiência da inicialização do aplicativo.

3. **Método de Configuração**: A anotação `@Lazy` pode ser aplicada a um método de configuração de bean, como um método anotado com `@Bean` em uma classe de configuração, ou pode ser aplicada diretamente a uma classe anotada com `@Component`, `@Service`, `@Repository`, etc.

4. **Considerações**: Use a anotação `@Lazy` com cuidado, pois a inicialização preguiçosa pode ser útil em cenários específicos, mas pode causar problemas se não for usada adequadamente. Certifique-se de entender bem o comportamento de inicialização dos seus beans ao aplicar `@Lazy`.

5. **Outras Abordagens**: Além do uso de `@Lazy`, você também pode configurar a inicialização preguiçosa de beans por meio de XML ou programaticamente usando o método `setLazyInit(true)` em um bean definido em XML.

Em resumo, a anotação `@Lazy` é usada para adiar a inicialização de um bean até que ele seja solicitado, o que pode ser útil para economizar recursos e melhorar o desempenho em aplicativos com muitos beans, especialmente quando nem todos os beans são necessários imediatamente.

--- 

## Classe de Teste de integração `AnimeControllerIT`

```java
package com.daniel.springbootessentials.integration;

import java.util.List;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;

import com.daniel.springbootessentials.domain.Anime;
import com.daniel.springbootessentials.domain.CustomUserDetails;
import com.daniel.springbootessentials.repository.AnimeRepository;
import com.daniel.springbootessentials.repository.CustomUserDetailsRepository;
import com.daniel.springbootessentials.requests.AnimePostRequestBody;
import com.daniel.springbootessentials.util.AnimeCreator;
import com.daniel.springbootessentials.util.AnimePostRequestBodyCreator;
import com.daniel.springbootessentials.wrapper.PageableResponse;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class AnimeControllerIT {

    @Autowired
    @Qualifier(value = "testRestTemplateRoleAdmin")
    private TestRestTemplate testRestTemplateRoleAdmin;

    @Autowired
    @Qualifier(value = "testRestTemplateRoleUser")
    private TestRestTemplate testRestTemplateRoleUser;

    @Autowired
    private AnimeRepository animeRepository;

    @Autowired
    private CustomUserDetailsRepository customUserDetailsRepository;


    private static CustomUserDetails ADMIN = CustomUserDetails.builder()
            .name("Daniel")
            .password("{bcrypt}$2a$10$0eykM.E9h17yruE6rkjrrezEUysVWasDjekzXto7cCk9wABM0cPLG")
            .username("daniel")
            .authorities("ROLE_ADMIN, ROLE_USER")
            .build();

    private static CustomUserDetails USER = CustomUserDetails.builder()
            .name("Biana")
            .password("{bcrypt}$2a$10$0eykM.E9h17yruE6rkjrrezEUysVWasDjekzXto7cCk9wABM0cPLG")
            .username("biana")
            .authorities("ROLE_USER")
            .build();

    @TestConfiguration
    @Lazy
    static class Config{
       
        @Bean(name = "testRestTemplateRoleAdmin")
        public TestRestTemplate testRestTemplateRoleAdminCreator(@Value("${local.server.port}") int port){
            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder()
                    .rootUri("http://localhost:" + port)
                    .basicAuthentication("daniel", "admin");
                    
            return new TestRestTemplate(restTemplateBuilder);
        }

        @Bean(name = "testRestTemplateRoleUser")
        public TestRestTemplate testRestTemplateRoleUserCreator(@Value("${local.server.port}") int port){
            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder()
                    .rootUri("http://localhost:" + port)
                    .basicAuthentication("biana", "admin");
                    
            return new TestRestTemplate(restTemplateBuilder);
        }
    }

    @Test
    @DisplayName("List returns list of anime inside page object when successful")
    void list_ReturnsListOfanimesInsidePageObject_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();

        PageableResponse<Anime> animePage = testRestTemplateRoleUser.exchange("/animes", HttpMethod.GET, null,
                new ParameterizedTypeReference<PageableResponse<Anime>>() {
                }).getBody();

        Assertions.assertThat(animePage).isNotNull();
        Assertions.assertThat(animePage.toList()).isNotEmpty().hasSize(1);
        Assertions.assertThat(animePage.toList().get(0).getName()).isEqualTo(expectedName);
    }
    
    // Teste para listar anime sem paginação
    @Test
    @DisplayName("List returns list of anime when successful")
    void listAll_ReturnsListOfanimes_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();

        List<Anime> animes = testRestTemplateRoleUser.exchange("/animes/all", HttpMethod.GET, null,
                new ParameterizedTypeReference<List<Anime>>() {
                }).getBody();

        Assertions.assertThat(animes).isNotNull().isNotEmpty().hasSize(1);
        Assertions.assertThat(animes.get(0).getName()).isEqualTo(expectedName);
    }

    // Teste para buscar anime por id não autenticado
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessful() {

       Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

       customUserDetailsRepository.save(USER);
       
       Long expectedId = savedAnime.getId();

       Anime anime = testRestTemplateRoleUser.getForObject("/animes/{id}", Anime.class, expectedId);

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }

    // Teste para buscar anime por id com autenticação
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessfulWithAuthenticated() {

       Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

       customUserDetailsRepository.save(ADMIN);
       
       Long expectedId = savedAnime.getId();

       Anime anime = testRestTemplateRoleAdmin.getForObject("/animes/admin/by-id/{id}", Anime.class, expectedId);

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }
    
    // Teste para salvar anime 
    @Test
    @DisplayName("save returns anime when successful")
    void save_ReturnsAnime_whenSuccessful() {

        customUserDetailsRepository.save(ADMIN);

        AnimePostRequestBody animePostRequestBody = AnimePostRequestBodyCreator.createAnimePostRequestBody();

        ResponseEntity<Anime> animeResponseEntity = testRestTemplateRoleAdmin.postForEntity("/animes/admin", animePostRequestBody, Anime.class);

        Assertions.assertThat(animeResponseEntity).isNotNull();
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.CREATED);  
        Assertions.assertThat(animeResponseEntity.getBody()).isNotNull();
        Assertions.assertThat(animeResponseEntity.getBody().getId()).isNotNull();
    }

    // Teste para buscar anime por nome
    @Test
    @DisplayName("findByNome returns a list of anime when successful")
    void findByNome_ReturnsListOfAnime_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();
    
        ResponseEntity<List<Anime>> response = testRestTemplateRoleUser.exchange("/animes/find/{name}", HttpMethod.GET, null, 
                new ParameterizedTypeReference<List<Anime>>() {}, expectedName);
    
        List<Anime> animes = response.getBody();
    
        Assertions.assertThat(animes).isNotNull().isNotEmpty().hasSize(1);
        Assertions.assertThat(animes.get(0).getName()).isEqualTo(expectedName);
    }    

    // Teste para buscar anime por nome não encontrado 
    @Test
    @DisplayName("findByNome returns an empty list of anime is not found")
    void findByNome_ReturnsEmptyListOfAnime_whenIsNotFound() {

        customUserDetailsRepository.save(USER);

        String url = String.format("/animes/find/dbz");

        ResponseEntity<List<Anime>> response = testRestTemplateRoleUser.exchange(
            url, HttpMethod.GET, null, new ParameterizedTypeReference<List<Anime>>() {}
    );

    // Verificações
    Assertions.assertThat(response.getStatusCodeValue()).isEqualTo(HttpStatus.OK.value());
    Assertions.assertThat(response.getBody()).isNotNull().isEmpty();
    }


    // Teste para atualizar anime 
    @Test
    @DisplayName("replace update anime when successful")
    void replace_UpdatesAnime_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());
        
        customUserDetailsRepository.save(ADMIN);

        savedAnime.setName("Dragon Ball Heroes");

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleAdmin.exchange("/animes/admin", HttpMethod.PUT, new HttpEntity<>(savedAnime), Void.class);

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    // Teste bem sucedido para deletar anime por id testado por um admin
    @Test
    @DisplayName("delete removes anime when successful")
    void delete_RemovesAnime_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(ADMIN);

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleAdmin.exchange("/animes/admin/{id}", HttpMethod.DELETE, null, Void.class, savedAnime.getId());

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

     
    // Teste não sucedido para deletar anime por id testado por um user
    @Test
    @DisplayName("delete removes anime when successful")
    void delete_Returns403_whenUserIsNotAdmin() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleUser.exchange("/animes/admin/{id}", HttpMethod.DELETE, null, Void.class, savedAnime.getId());

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
}
```
<hr color="red">
<br />

Explicando o que cada parte faz:

```java
package com.daniel.springbootessentials.integration;

imports...

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class AnimeControllerIT {
    ...
}
```

Explicando as anotações declaradas na classe `AnimeControllerIT`:

1. `@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)`

   - `@SpringBootTest`: Essa anotação é usada para indicar que a classe é um teste de integração que envolve a inicialização do contexto da aplicação Spring. Em outras palavras, ela carrega a configuração do aplicativo Spring para permitir que teste componentes da aplicação de forma integrada.

   - `webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT`: Esta parte da anotação define o ambiente de execução para o teste de integração. `RANDOM_PORT` indica que o teste será executado em uma porta aleatória, o que é útil para evitar conflitos de porta quando vários testes estão sendo executados simultaneamente. Isso é comumente usado quando você deseja testar interações com seu aplicativo por meio de solicitações HTTP.

2. `@AutoConfigureTestDatabase`

   - `@AutoConfigureTestDatabase`: Esta anotação é usada para configurar automaticamente um banco de dados de teste para o seu teste de integração. O Spring Boot detectará o tipo de banco de dados que está usando em seu aplicativo e configurará um banco de dados de teste correspondente para ser usado durante o teste. Isso permite que você execute testes em um ambiente isolado e controlado.

3. `@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)`

   - `@DirtiesContext`: Esta anotação é usada para indicar ao Spring que o contexto da aplicação deve ser "sujado" ou reiniciado antes de cada método de teste. Isso garante que cada método de teste seja executado em um contexto limpo e isolado, evitando que os efeitos colaterais dos testes afetem uns aos outros.

   - `classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD`: Esta parte da anotação especifica o modo em que o contexto da aplicação será "sujado". Neste caso, o contexto será sujado antes de cada método de teste individual (`BEFORE_EACH_TEST_METHOD`), garantindo um ambiente limpo para cada teste.

Em resumo, essas anotações são usadas para configurar e executar um teste de integração Spring Boot. Elas definem o ambiente de execução, configuram um banco de dados de teste e garantem que o contexto da aplicação seja reiniciado antes de cada método de teste, proporcionando um ambiente controlado e isolado para seus testes de integração.

<hr color="red">
<br />

```java
package com.daniel.springbootessentials.integration;

imports...

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class AnimeControllerIT {

    @Autowired
    @Qualifier(value = "testRestTemplateRoleAdmin")
    private TestRestTemplate testRestTemplateRoleAdmin;

    @Autowired
    @Qualifier(value = "testRestTemplateRoleUser")
    private TestRestTemplate testRestTemplateRoleUser;

    @Autowired
    private AnimeRepository animeRepository;

    @Autowired
    private CustomUserDetailsRepository customUserDetailsRepository;

    ...
}
```

As declarações acima são anotações `@Autowired` que são usadas para injetar dependências em uma classe de teste Spring. 

Explicação detalhada de cada uma delas:

1. `@Autowired @Qualifier(value = "testRestTemplateRoleAdmin") private TestRestTemplate testRestTemplateRoleAdmin;`

   - `@Autowired`: Esta anotação é usada para injetar uma dependência em uma classe Spring. No contexto de testes, o Spring injetará automaticamente uma instância do tipo apropriado no campo marcado com esta anotação.

   - `@Qualifier(value = "testRestTemplateRoleAdmin")`: O `@Qualifier` é usado para especificar qual bean específico deve ser injetado quando há várias instâncias do mesmo tipo no contexto do Spring. Neste caso, estamos qualificando o bean `testRestTemplateRoleAdmin` usando seu nome "testRestTemplateRoleAdmin". Isso é necessário porque existem dois beans `TestRestTemplate` definidos na classe de configuração de teste.

   - `private TestRestTemplate testRestTemplateRoleAdmin;`: Este é o campo onde a instância do bean `TestRestTemplate` será injetada. Ele será usado nos métodos de teste para fazer solicitações HTTP como um usuário com privilégios de administrador.

2. `@Autowired @Qualifier(value = "testRestTemplateRoleUser") private TestRestTemplate testRestTemplateRoleUser;`

   - Similar ao primeiro, este campo injeta uma instância de `TestRestTemplate`, mas desta vez é configurado para representar um usuário com privilégios de usuário regular.

3. `@Autowired private AnimeRepository animeRepository;`

   - Este campo injeta uma instância de `AnimeRepository`. É usado para interagir com o banco de dados e realizar operações relacionadas aos animes durante os testes.

4. `@Autowired private CustomUserDetailsRepository customUserDetailsRepository;`

   - Este campo injeta uma instância de `CustomUserDetailsRepository`. É usado para interagir com o banco de dados e realizar operações relacionadas aos detalhes dos usuários durante os testes.

No geral, essas declarações de injeção de dependência permitem que acessar e utilizar as instâncias corretas de `TestRestTemplate`, `AnimeRepository` e `CustomUserDetailsRepository` nos métodos de teste para simular interações com o aplicativo e verificar seu comportamento. O uso de `@Qualifier` é necessário para distingui-los quando há várias implementações disponíveis do mesmo tipo de bean no contexto de teste.

<hr color="red">
<br />

```java
package com.daniel.springbootessentials.integration;

imports...

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class AnimeControllerIT {

    ...

    private static CustomUserDetails ADMIN = CustomUserDetails.builder()
            .name("Daniel")
            .password("{bcrypt}$2a$10$0eykM.E9h17yruE6rkjrrezEUysVWasDjekzXto7cCk9wABM0cPLG")
            .username("daniel")
            .authorities("ROLE_ADMIN, ROLE_USER")
            .build();

    private static CustomUserDetails USER = CustomUserDetails.builder()
            .name("Biana")
            .password("{bcrypt}$2a$10$0eykM.E9h17yruE6rkjrrezEUysVWasDjekzXto7cCk9wABM0cPLG")
            .username("biana")
            .authorities("ROLE_USER")
            .build();
    ...
}
```

O código acima cria duas instâncias de `CustomUserDetails`, uma para um usuário com privilégios de administrador (ADMIN) e outra para um usuário com privilégios de usuário regular (USER). 

Explicação detalhada do que está acontecendo:

1. `private static CustomUserDetails ADMIN = CustomUserDetails.builder()`
   - Este é o início da criação da instância `ADMIN` de `CustomUserDetails` usando o padrão de construção do tipo Builder.

2. `.name("Daniel")`
   - Define o nome do usuário como "Daniel".

3. `.password("{bcrypt}$2a$10$0eykM.E9h17yruE6rkjrrezEUysVWasDjekzXto7cCk9wABM0cPLG")`
   - Define a senha do usuário. A senha está usando a codificação bcrypt, o que é comum para armazenamento seguro de senhas. O valor após `{bcrypt}` é a senha criptografada.

4. `.username("daniel")`
   - Define o nome de usuário como "daniel".

5. `.authorities("ROLE_ADMIN, ROLE_USER")`
   - Define as autorizações (ou papéis) atribuídas a este usuário. Neste caso, o usuário ADMIN tem as autorizações "ROLE_ADMIN" e "ROLE_USER". As autorizações são usadas para controlar o acesso a recursos e funcionalidades em um aplicativo Spring Security.

6. `.build();`
   - Este método `build()` finaliza a construção da instância `ADMIN` de `CustomUserDetails` e a armazena na variável `ADMIN`.

Os mesmos passos são seguidos para criar a instância `USER` de `CustomUserDetails`, mas esta tem apenas a autorização "ROLE_USER" e é associada ao nome "Biana" e ao nome de usuário "biana".

Essas instâncias são usadas em testes para simular diferentes tipos de usuários (administrador e usuário regular) ao interagir com o aplicativo durante os testes de integração. Isso permite verificar se o aplicativo responde a diferentes tipos de usuários e suas autorizações.

<hr color="red">
<br />

```java
package com.daniel.springbootessentials.integration;

imports...

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class AnimeControllerIT {

    ...

    @TestConfiguration
    @Lazy
    static class Config{
       
        @Bean(name = "testRestTemplateRoleAdmin")
        public TestRestTemplate testRestTemplateRoleAdminCreator(@Value("${local.server.port}") int port){
            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder()
                    .rootUri("http://localhost:" + port)
                    .basicAuthentication("daniel", "admin");
                    
            return new TestRestTemplate(restTemplateBuilder);
        }

        @Bean(name = "testRestTemplateRoleUser")
        public TestRestTemplate testRestTemplateRoleUserCreator(@Value("${local.server.port}") int port){
            RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder()
                    .rootUri("http://localhost:" + port)
                    .basicAuthentication("biana", "admin");
                    
            return new TestRestTemplate(restTemplateBuilder);
        }
    }

    ...
}
```

O código acima cria duas instâncias de `TestRestTemplate` configuradas com autenticação básica para serem usadas nos testes. 

Explicação detalhada do que está acontecendo:

1. `@TestConfiguration`
   - Essa anotação indica que a classe `Config` é uma classe de configuração usada especificamente para configurações de teste. Ela faz parte do sistema de configuração do Spring para testes e permite que você defina configurações específicas para o ambiente de teste.

2. `@Lazy`
   - Essa anotação marca a classe `Config` como sendo inicializada sob demanda (lazy). Isso significa que a classe `Config` só será criada quando for solicitada, o que pode economizar recursos se não for usada em todos os casos de teste.

3. `@Bean(name = "testRestTemplateRoleAdmin")`
   - Esta anotação marca o método `testRestTemplateRoleAdminCreator` como um método de criação de bean Spring. O nome `testRestTemplateRoleAdmin` é usado como o nome do bean. Isso significa que pode injetar essa instância de `TestRestTemplate` em outros componentes da aplicação usando o nome `testRestTemplateRoleAdmin`.

5. `public TestRestTemplate testRestTemplateRoleAdminCreator(@Value("${local.server.port}") int port) { ... }`
   - Este método cria uma instância de `TestRestTemplate` configurada para um usuário com privilégios de administrador (ROLE_ADMIN). O valor da porta é injetado usando a anotação `@Value("${local.server.port}")`, o que permite que o teste se comunique com o servidor local na porta em que a aplicação está sendo executada.

6. `RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder() ...`
   - Aqui, um `RestTemplateBuilder` é criado para configurar a instância de `TestRestTemplate`. O `RestTemplateBuilder` é uma classe utilizada para configurar e criar instâncias de `RestTemplate`, que são usadas para fazer chamadas HTTP.

7. `.rootUri("http://localhost:" + port)`
   - Define a raiz URI para todas as chamadas HTTP feitas por esta instância de `TestRestTemplate`. Neste caso, a raiz URI é definida como "http://localhost" seguida pela porta injetada a partir de `${local.server.port}`.

8. `.basicAuthentication("daniel", "admin")`
   - Configura a autenticação básica para esta instância de `TestRestTemplate`. Isso significa que as solicitações feitas por esta instância serão autenticadas com o nome de usuário "daniel" e a senha "admin".

9. `return new TestRestTemplate(restTemplateBuilder);`
   - Finalmente, o método cria uma instância de `TestRestTemplate` com as configurações definidas e a retorna como um bean Spring.

O mesmo processo é repetido para o método `testRestTemplateRoleUserCreator`, mas esta instância de `TestRestTemplate` é configurada para um usuário com privilégios de usuário regular (ROLE_USER). As duas instâncias podem ser usadas nos testes para simular diferentes tipos de usuários e suas interações com o aplicativo durante os testes de integração.

<hr color="red">
<br />

Os métodos de teste que testam várias funcionalidades do controlador `AnimeController` em um ambiente de teste de integração. Cada método de teste é marcado com a anotação `@Test` e fornece uma descrição do que está sendo testado usando a anotação `@DisplayName`. 

Explicação detalhada de cada método de teste:

1. `list_ReturnsListOfanimesInsidePageObject_whenSuccessful()`
   - Este método testa se a rota `/animes` retorna uma lista de animes dentro de um objeto de página (usando paginação) quando a solicitação é bem-sucedida para um usuário com privilégios de usuário (ROLE_USER).
   - Um anime é salvo no repositório de animes (`animeRepository`).
   - Um usuário com privilégios de usuário (ROLE_USER) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - O método `exchange` do `TestRestTemplate` é usado para fazer uma solicitação GET para `/animes`.
   - As respostas são verificadas para garantir que a resposta não seja nula, que a lista de animes não esteja vazia e que o nome do anime na lista corresponda ao nome esperado.

```java
@Test
    @DisplayName("List returns list of anime inside page object when successful")
    void list_ReturnsListOfanimesInsidePageObject_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();

        PageableResponse<Anime> animePage = testRestTemplateRoleUser.exchange("/animes", HttpMethod.GET, null,
                new ParameterizedTypeReference<PageableResponse<Anime>>() {
                }).getBody();

        Assertions.assertThat(animePage).isNotNull();
        Assertions.assertThat(animePage.toList()).isNotEmpty().hasSize(1);
        Assertions.assertThat(animePage.toList().get(0).getName()).isEqualTo(expectedName);
    }
```
<hr color="red">
<br />

2. `listAll_ReturnsListOfanimes_whenSuccessful()`
   - Este método testa se a rota `/animes/all` retorna uma lista de animes quando a solicitação é bem-sucedida para um usuário com privilégios de usuário (ROLE_USER).
   - Um anime é salvo no repositório de animes (`animeRepository`).
   - Um usuário com privilégios de usuário (ROLE_USER) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - O método `exchange` do `TestRestTemplate` é usado para fazer uma solicitação GET para `/animes/all`.
   - As respostas são verificadas para garantir que a resposta não seja nula, que a lista de animes não esteja vazia e que o nome do anime na lista corresponda ao nome esperado.

```java
// Teste para listar anime sem paginação
    @Test
    @DisplayName("List returns list of anime when successful")
    void listAll_ReturnsListOfanimes_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();

        List<Anime> animes = testRestTemplateRoleUser.exchange("/animes/all", HttpMethod.GET, null,
                new ParameterizedTypeReference<List<Anime>>() {
                }).getBody();

        Assertions.assertThat(animes).isNotNull().isNotEmpty().hasSize(1);
        Assertions.assertThat(animes.get(0).getName()).isEqualTo(expectedName);
    }
```
<hr color="red">
<br />

3. `findById_ReturnsAnime_whenSuccessful()`
   - Este método testa se a rota `/animes/{id}` retorna um anime quando a solicitação é bem-sucedida para um usuário com privilégios de usuário (ROLE_USER).
   - Um anime é salvo no repositório de animes (`animeRepository`).
   - Um usuário com privilégios de usuário (ROLE_USER) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - O método `getForObject` do `TestRestTemplate` é usado para fazer uma solicitação GET para `/animes/{id}`.
   - A resposta é verificada para garantir que o anime retornado não seja nulo e que o ID do anime corresponda ao ID esperado.

```java
// Teste para buscar anime por id não autenticado
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessful() {

       Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

       customUserDetailsRepository.save(USER);
       
       Long expectedId = savedAnime.getId();

       Anime anime = testRestTemplateRoleUser.getForObject("/animes/{id}", Anime.class, expectedId);

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }
```

<hr color="red">
<br />

4. `findById_ReturnsAnime_whenSuccessfulWithAuthenticated()`
   - Este método é semelhante ao método anterior, mas testa a rota `/animes/admin/by-id/{id}` para um usuário autenticado com privilégios de administrador (ROLE_ADMIN).
   - Um usuário com privilégios de administrador (ROLE_ADMIN) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - A rota `/animes/admin/by-id/{id}` é usada para recuperar um anime por ID.

```java
// Teste para buscar anime por id com autenticação
    @Test
    @DisplayName("findById returns anime when successful")
    void findById_ReturnsAnime_whenSuccessfulWithAuthenticated() {

       Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

       customUserDetailsRepository.save(ADMIN);
       
       Long expectedId = savedAnime.getId();

       Anime anime = testRestTemplateRoleAdmin.getForObject("/animes/admin/by-id/{id}", Anime.class, expectedId);

        Assertions.assertThat(anime).isNotNull();
        Assertions.assertThat(anime.getId()).isNotNull().isEqualTo(expectedId);
    }
```

<hr color="red">
<br />

5. `save_ReturnsAnime_whenSuccessful()`
   - Este método testa se a rota `/animes/admin` retorna um anime quando a solicitação de salvamento é bem-sucedida para um usuário com privilégios de administrador (ROLE_ADMIN).
   - Um usuário com privilégios de administrador (ROLE_ADMIN) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - Um objeto `AnimePostRequestBody` é criado para representar os dados de um anime.
   - O método `postForEntity` do `TestRestTemplate` é usado para fazer uma solicitação POST para `/animes/admin`.
   - A resposta é verificada para garantir que o anime retornado não seja nulo e que o código de status HTTP seja 201 (CREATED).

```java
// Teste para salvar anime 
    @Test
    @DisplayName("save returns anime when successful")
    void save_ReturnsAnime_whenSuccessful() {

        customUserDetailsRepository.save(ADMIN);

        AnimePostRequestBody animePostRequestBody = AnimePostRequestBodyCreator.createAnimePostRequestBody();

        ResponseEntity<Anime> animeResponseEntity = testRestTemplateRoleAdmin.postForEntity("/animes/admin", animePostRequestBody, Anime.class);

        Assertions.assertThat(animeResponseEntity).isNotNull();
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.CREATED);  
        Assertions.assertThat(animeResponseEntity.getBody()).isNotNull();
        Assertions.assertThat(animeResponseEntity.getBody().getId()).isNotNull();
    }
```

<hr color="red">
<br />

6. `findByNome_ReturnsListOfAnime_whenSuccessful()`
   - Este método testa se a rota `/animes/find/{name}` retorna uma lista de animes quando a solicitação é bem-sucedida para um usuário com privilégios de usuário (ROLE_USER).
   - Um anime é salvo no repositório de animes (`animeRepository`).
   - Um usuário com privilégios de usuário (ROLE_USER) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - O método `exchange` do `TestRestTemplate` é usado para fazer uma solicitação GET para `/animes/find/{name}` com o nome do anime como parâmetro.
   - A resposta é verificada para garantir que a resposta não seja nula, que a lista de animes não esteja vazia e que o nome do anime na lista corresponda ao nome esperado.

```java
// Teste para buscar anime por nome
    @Test
    @DisplayName("findByNome returns a list of anime when successful")
    void findByNome_ReturnsListOfAnime_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        String expectedName = savedAnime.getName();
    
        ResponseEntity<List<Anime>> response = testRestTemplateRoleUser.exchange("/animes/find/{name}", HttpMethod.GET, null, 
                new ParameterizedTypeReference<List<Anime>>() {}, expectedName);
    
        List<Anime> animes = response.getBody();
    
        Assertions.assertThat(animes).isNotNull().isNotEmpty().hasSize(1);
        Assertions.assertThat(animes.get(0).getName()).isEqualTo(expectedName);
    }
```

<hr color="red">
<br />

7. `findByNome_ReturnsEmptyListOfAnime_whenIsNotFound()`
   - Este método testa se a rota `/animes/find/{name}` retorna uma lista vazia de animes quando a solicitação não encontra nenhum anime correspondente para um usuário com privilégios de usuário (ROLE_USER).
   - Um usuário com privilégios de usuário (ROLE_USER) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - O método `exchange` do `TestRestTemplate` é usado para fazer uma solicitação GET para `/animes/find/dbz`, que é improvável que corresponda a nenhum anime existente.
   - A resposta é verificada para garantir que o código de status HTTP seja 200 (OK) e que a lista de animes seja vazia.

```java
// Teste para buscar anime por nome não encontrado 
    @Test
    @DisplayName("findByNome returns an empty list of anime is not found")
    void findByNome_ReturnsEmptyListOfAnime_whenIsNotFound() {

        customUserDetailsRepository.save(USER);

        String url = String.format("/animes/find/dbz");

        ResponseEntity<List<Anime>> response = testRestTemplateRoleUser.exchange(
            url, HttpMethod.GET, null, new ParameterizedTypeReference<List<Anime>>() {}
    );

    // Verificações
    Assertions.assertThat(response.getStatusCodeValue()).isEqualTo(HttpStatus.OK.value());
    Assertions.assertThat(response.getBody()).isNotNull().isEmpty();
    }
```

<hr color="red">
<br />

8. `replace_UpdatesAnime_whenSuccessful()`
   - Este método testa se a rota `/animes/admin` atualiza um anime com sucesso quando a solicitação é feita por um usuário com privilégios de administrador (ROLE_ADMIN).
   - Um anime é salvo no repositório de animes (`animeRepository`).
   - Um usuário com privilégios de administrador (ROLE_ADMIN) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - O nome do anime é atualizado para "Dragon Ball Heroes".
   - O método `exchange` do `TestRestTemplate` é usado para fazer uma solicitação PUT para `/animes/admin`.
   - A resposta é verificada para garantir que o código de status HTTP seja 204 (NO CONTENT).

```java
// Teste para atualizar anime 
    @Test
    @DisplayName("replace update anime when successful")
    void replace_UpdatesAnime_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());
        
        customUserDetailsRepository.save(ADMIN);

        savedAnime.setName("Dragon Ball Heroes");

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleAdmin.exchange("/animes/admin", HttpMethod.PUT, new HttpEntity<>(savedAnime), Void.class);

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }
```

<hr color="red">
<br />

9. `delete_RemovesAnime_whenSuccessful()`
   - Este método testa se a rota `/animes/admin/{id}` remove um anime com sucesso quando a solicitação é feita por um usuário com privilégios de administrador (ROLE_ADMIN).
   - Um anime é salvo no repositório de animes (`animeRepository`).
   - Um usuário com privilégios de administrador (ROLE_ADMIN) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
   - O método `exchange` do `TestRestTemplate` é usado para fazer uma solicitação DELETE para `/animes/admin/{id}`.
   - A resposta é verificada para garantir que o código de status HTTP seja 204 (NO CONTENT).

```java
@Test
    @DisplayName("delete removes anime when successful")
    void delete_RemovesAnime_whenSuccessful() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(ADMIN);

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleAdmin.exchange("/animes/admin/{id}", HttpMethod.DELETE, null, Void.class, savedAnime.getId());

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }
```

<hr color="red">
<br />

10. `delete_Returns403_whenUserIsNotAdmin()`
    - Este método testa se a rota `/animes/admin/{id}` retorna um código de status 403 (FORBIDDEN) quando a solicitação é feita por um usuário com privilégios de usuário regular (ROLE_USER).
    - Um anime é salvo no repositório de animes (`animeRepository`).
    - Um usuário com privilégios de usuário (ROLE_USER) é salvo no repositório de detalhes do usuário (`customUserDetailsRepository`).
    - O método `exchange` do `TestRestTemplate` é usado para fazer uma solicitação DELETE para `/animes/admin/{id}`.
    - A resposta é verificada para garantir que o código de status HTTP seja 403 (FORBIDDEN).

```java
// Teste não sucedido para deletar anime por id testado por um user
    @Test
    @DisplayName("delete removes anime when successful")
    void delete_Returns403_whenUserIsNotAdmin() {

        Anime savedAnime = animeRepository.save(AnimeCreator.createAnimeToBeSaved());

        customUserDetailsRepository.save(USER);

        ResponseEntity<Void> animeResponseEntity = testRestTemplateRoleUser.exchange("/animes/admin/{id}", HttpMethod.DELETE, null, Void.class, savedAnime.getId());

        Assertions.assertThat(animeResponseEntity).isNotNull();  
        Assertions.assertThat(animeResponseEntity.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
```

Esses métodos de teste são executados em um ambiente de teste de integração e verificam o comportamento do controlador `AnimeController` em várias situações, incluindo diferentes tipos de autenticação, recuperação de dados e operações CRUD.