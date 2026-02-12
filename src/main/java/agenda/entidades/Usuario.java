package agenda.entidades;

public class Usuario {
    String username;
    String encryptedPass;
    Rol rol;
    public Usuario(String username, String encryptedPass, Rol rol) {
        this.username = username;
        this.encryptedPass = encryptedPass;
        this.rol = rol;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getEncryptedPass() {
        return encryptedPass;
    }
    public void setEncryptedPass(String encryptedPass) {
        this.encryptedPass = encryptedPass;
    }
    public Rol getRol() {
        return rol;
    }
    public void setRol(Rol rol) {
        this.rol = rol;
    }
    @Override
    public String toString() {
        return "Usuario{" +
                "username='" + username + '\'' +
                ", encryptedPass='" + encryptedPass + '\'' +
                ", rol=" + rol +
                '}';
    }

    public enum Rol {
        ADMIN("ADMIN"),
        USER("USER");
        private final String rol;
        Rol(String rol) {
            this.rol = rol;
        }
        public String getRol() {
            return rol;
        }
    }


}