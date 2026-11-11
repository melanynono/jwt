
package com.krakedev.jwt.services;

import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;

import org.mindrot.jbcrypt.BCrypt;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    public Usuario registrar(Usuario usuario) {

        String passwordHash = BCrypt.hashpw(
                usuario.getPassword(),
                BCrypt.gensalt()
        );

        usuario.setPassword(passwordHash);

        return usuarioRepository.save(usuario);
    }

    public boolean autenticar(String username, String password) {

        Usuario usuario = usuarioRepository.findByUsername(username);

        if (usuario != null &&
                BCrypt.checkpw(password, usuario.getPassword())) {
            return true;
        }

        return false;
    }
}
