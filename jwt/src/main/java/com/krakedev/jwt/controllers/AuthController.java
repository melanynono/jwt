
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

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsuarioService usuarioService;

    public AuthController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
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
    public ResponseEntity<?> login(@RequestBody Usuario usuario) {

        Usuario usuarioAutenticado = usuarioService.login(
                usuario.getUsername(),
                usuario.getPassword()
        );

        if (usuarioAutenticado != null) {
            return ResponseEntity.ok(
                Map.of(
                    "mensaje", "Inicio de sesión exitoso",
                    "username", usuarioAutenticado.getUsername(),
                    "rol", usuarioAutenticado.getRol()
                )
            );
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Usuario o contraseña incorrectos");
    }
}
