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