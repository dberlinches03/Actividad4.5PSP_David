Parte 2: Modificación del Servidor HTTP con Spring Boot
1. Proceso seguido para implementar la modificación (PUT)
Para implementar la operación PUT que permite actualizar el número de teléfono de un contacto, seguí estos pasos:

a) Añadir el método en el repositorio
Incorporé un método actualizar(Long id, Contacto contacto) en la interfaz ContactoRepository y lo implementé en ContactoRepositoryImpl.
La implementación comprueba si el contacto existe en el Map y, si es así, reemplaza sus datos.

b) Añadir el método en el servicio
Añadí el método actualizar() en ContactoService y lo implementé en ContactoServiceImpl, delegando la operación al repositorio.

c) Crear el endpoint PUT en el controlador
En ContactoController añadí un método anotado con @PutMapping("/{id}") que recibe el ID por URL y el contacto actualizado en el cuerpo de la petición.

d) Añadir el método en el cliente Java
Implementé el método modificarContacto() usando RestTemplate.exchange() con HttpMethod.PUT.
Luego lo llamé desde realizarPruebas() para verificar que el servidor actualiza correctamente el contacto.

e) Pruebas
Probé el flujo completo:

Crear contacto

Modificarlo

Verificar que el servidor devuelve el contacto actualizado

2. ¿Cómo sabe el servidor si tiene que leer o actualizar un contacto?
Aunque la ruta es la misma:

Código
/contactos/{id}
El servidor distingue la operación por el método HTTP utilizado en la petición:

Método	Acción
GET	Leer un contacto por ID
PUT	Actualizar un contacto por ID
Spring Boot selecciona automáticamente el método correcto gracias a las anotaciones:

@GetMapping("/{id}")

@PutMapping("/{id}")

Por tanto, la diferencia no está en la ruta, sino en el verbo HTTP.

3. ¿Qué significa @RequestMapping("/contactos") en el controlador?
@RequestMapping("/contactos") indica que todas las rutas del controlador comienzan con:
/contactos

Es una forma de agrupar todas las operaciones relacionadas con la entidad Contacto bajo un mismo prefijo.
Gracias a esto, las rutas finales quedan así:

GET /contactos

GET /contactos/{id}

POST /contactos

PUT /contactos/{id}

DELETE /contactos/{id}

Sirve para organizar mejor la API y evitar repetir el prefijo en cada método.
