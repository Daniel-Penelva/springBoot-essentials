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