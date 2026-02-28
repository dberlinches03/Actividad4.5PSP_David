package agenda.controladores;

import agenda.entidades.Usuario;
import agenda.repositorios.UsuarioRepository;
import agenda.seguridad.Constans;
import agenda.seguridad.JWTAuthenticationConfig;
import agenda.seguridad.PasswordEncryptor;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class LoginController {

    @Autowired
    JWTAuthenticationConfig jwtAuthenticationConfig;

    @Autowired
    UsuarioRepository usuarioRepository;

    @PostMapping("login")
    public String login(@RequestParam("user") String username, @RequestParam("encryptedPass") String encryptedPass) throws BadRequestException {
        List<Usuario> usuarios = usuarioRepository.getUsuarios();
        Usuario usuarioEncontrado = null;
        for (Usuario usuario : usuarios) {
            if (usuario.getUsername().equals(username) &&
                    PasswordEncryptor.decrypt(usuario.getEncryptedPass()).equals(encryptedPass)) {
                usuarioEncontrado = usuario;
                break;
            }
        }
        if (usuarioEncontrado == null) {
            throw new BadRequestException();
        }
        String token = jwtAuthenticationConfig.getJWTToken(usuarioEncontrado.getUsername(), usuarioEncontrado.getRol());
        return token;
    }
}
