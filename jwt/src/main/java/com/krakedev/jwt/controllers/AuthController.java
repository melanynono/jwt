package com.krakedev.jwt.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioService;
import com.krakedev.jwt.utils.JwtUtil;
import com.krakedev.jwt.repositories.UsuarioRepository;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import com.auth0.jwt.interfaces.DecodedJWT;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsuarioService usuarioService;
    private final UsuarioRepository usuarioRepository;

    public AuthController(UsuarioService usuarioService, UsuarioRepository usuarioRepository) {
        this.usuarioService = usuarioService;
		this.usuarioRepository = usuarioRepository;
    }

    @PostMapping("/registrar")
    public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {
        try {
            Usuario usuarioGuardado = usuarioService.registrar(usuario);

            return ResponseEntity.status(HttpStatus.CREATED).body(
                Map.of(
                    "mensaje", "Usuario registrado correctamente",
                    "username", usuarioGuardado.getUsername(),
                    "rol", usuarioGuardado.getRol()
                )
            );

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error al registrar el usuario");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales) {

        String username = credenciales.get("username");
        String password = credenciales.get("password");

        boolean autenticado = usuarioService.autenticar(username, password);

        if (autenticado) {

            Usuario usuario = usuarioRepository.findByUsername(username);

            String token = JwtUtil.generarToken(
                    usuario.getUsername(),
                    usuario.getRol()
            );

            return ResponseEntity.ok(Map.of("token", token));

        } else {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Usuario o contraseña incorrecta");
        }
    }
    
    @GetMapping("/perfil")
    public ResponseEntity<?> perfil(
            @RequestHeader("Authorization") String authorization) {

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Token no proporcionado");
        }

        String token = authorization.substring(7);

        DecodedJWT tokenDecodificado = JwtUtil.validarToken(token);

        if (tokenDecodificado == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Token inválido o expirado");
        }

        String username = tokenDecodificado.getSubject();
        String rol = tokenDecodificado.getClaim("rol").asString();

        return ResponseEntity.ok(
            Map.of(
                "mensaje", "Bienvenido al perfil del voluntario",
                "username", username,
                "rol", rol
            )
        );
    }
}