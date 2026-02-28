package agenda.repositorios;

import agenda.entidades.Usuario;
import agenda.seguridad.PasswordEncryptor;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class UsuarioRepository {
    public List<Usuario> getUsuarios(){
        ArrayList<Usuario> usuarios = new ArrayList<Usuario>();
        usuarios.add(new Usuario("aitor",
                PasswordEncryptor.encrypt("1234"), Usuario.Rol.ADMIN));
        usuarios.add(new Usuario("alicia",
                PasswordEncryptor.encrypt("1111"), Usuario.Rol.USER));

        // Nuevo usuario para las pruebas
        usuarios.add(new Usuario("invitado",
                PasswordEncryptor.encrypt("guest123"), Usuario.Rol.GUEST));
        return usuarios;
    }
}