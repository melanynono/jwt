
package com.krakedev.jwt.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.krakedev.jwt.entidades.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {

    Usuario findByUsername(String username);

}
