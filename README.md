# Backend Django - Sistema de Inventario y Ventas

Backend desarrollado en Django REST Framework para el sistema de gestión de inventario y ventas.

## Características

- **Autenticación**: Sistema de autenticación basado en cookies con tokens firmados
- **Gestión de Usuarios**: CRUD completo de usuarios con roles y permisos
- **Sistema de Roles y Permisos**: Control de acceso basado en roles (ADMIN, VENDEDOR, CLIENTE)
- **Gestión de Productos**: Catálogo de productos con marcas, categorías y unidades
- **Inventario**: Control de lotes con fechas de vencimiento
- **Carrito de Compras**: Sistema de carrito para clientes
- **Órdenes**: Gestión de órdenes de compra
- **Alertas**: Sistema de alertas para stock bajo y productos próximos a vencer
- **Pagos**: Integración con Stripe para procesamiento de pagos
- **Auditoría**: Sistema de bitácora para registro de acciones

## Tecnologías Utilizadas

- Django 4.2.24
- Django REST Framework 3.16.1
- PostgreSQL (vía Railway)
- Stripe API para pagos
- Python 3.13.5

## Instalación

### 1. Clonar el repositorio

```bash
cd backend
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 3. Configurar variables de entorno

Edita el archivo `.env` con tus configuraciones:

```env
DATABASE_URL=postgresql://postgres:password@host:port/database
SECRET_KEY=tu-secret-key-aqui
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ALLOWED_ORIGINS=http://localhost:3000
STRIPE_SECRET_KEY=sk_test_tu_stripe_key
STRIPE_PUBLISHABLE_KEY=pk_test_tu_stripe_key
```

### 4. Ejecutar migraciones

```bash
python manage.py makemigrations
python manage.py migrate
```

### 5. Cargar datos iniciales

```bash
python init_data.py
```

Este comando crea:
- Roles: ADMIN, VENDEDOR, CLIENTE
- Permisos para cada rol
- Usuario administrador por defecto:
  - Email: `admin@example.com`
  - Password: `admin123`

### 6. Ejecutar el servidor

```bash
python manage.py runserver 8000
```

El servidor estará disponible en `http://localhost:8000`

## Estructura del Proyecto

```
backend/
├── api/
│   ├── models.py           # Modelos de la base de datos
│   ├── serializers.py      # Serializers de DRF
│   ├── views.py            # Vistas/endpoints de la API
│   ├── urls.py             # Rutas de la API
│   ├── middleware.py       # Middleware de autenticación
│   ├── utils.py            # Funciones utilitarias
│   └── admin.py            # Configuración del admin de Django
├── backend/
│   ├── settings.py         # Configuración del proyecto
│   ├── urls.py             # URLs principales
│   └── wsgi.py
├── init_data.py            # Script de datos iniciales
├── requirements.txt        # Dependencias
├── .env                    # Variables de entorno
└── manage.py
```

## Endpoints de la API

### Autenticación
- `POST /auth/login` - Iniciar sesión
- `POST /auth/logout` - Cerrar sesión
- `GET /me` - Obtener información del usuario actual

### Endpoints Públicos
- `POST /public/register` - Registrar nuevo usuario
- `GET /public/productos` - Listar productos (público)
- `GET /public/categorias` - Listar categorías

### Usuarios
- `GET /users` - Listar usuarios
- `POST /users/internal` - Crear usuario interno
- `PATCH /users/<id>` - Actualizar usuario
- `DELETE /users/<id>/delete` - Eliminar usuario
- `GET /users/clientes` - Listar clientes con paginación
- `GET /users/clientes/by-date-range` - Clientes por rango de fechas

### Roles y Permisos
- `GET /roles` - Listar roles
- `POST /roles/create` - Crear rol
- `GET /roles/<id>` - Obtener rol específico
- `PUT /roles/<id>/update` - Actualizar rol
- `DELETE /roles/<id>/delete` - Eliminar rol
- `GET /roles/<id>/permissions` - Obtener permisos del rol
- `PUT /roles/<id>/permissions/update` - Actualizar permisos del rol
- `GET /permissions` - Listar todos los permisos

### Carrito de Compras
- `GET /carrito` - Obtener carrito del usuario
- `POST /carrito/add` - Agregar producto al carrito
- `PATCH /carrito/<id>` - Actualizar cantidad
- `DELETE /carrito/<id>/delete` - Eliminar item del carrito
- `DELETE /carrito/clear` - Vaciar carrito
- `POST /carrito/checkout` - Crear orden desde el carrito

### Productos e Inventario
- `GET /productos/<id>/lotes` - Listar lotes de un producto
- `POST /productos/<id>/lotes/create` - Crear lote
- `PATCH /lotes/<id>` - Actualizar lote
- `DELETE /lotes/<id>/delete` - Eliminar lote

### Alertas
- `GET /alerts` - Listar alertas
- `PATCH /alerts/<id>/read` - Marcar alerta como leída
- `PATCH /alerts/read-all` - Marcar todas como leídas

### Bitácora (Auditoría)
- `GET /bitacora` - Listar logs de auditoría
- `POST /bitacora/create` - Crear entrada en bitácora

### Pagos
- `POST /pagos/crear` - Crear sesión de pago con Stripe
- `POST /pagos/confirmar` - Confirmar pago
- `GET /pagos/facturas` - Listar facturas
- `GET /pagos/factura/<id>` - Obtener factura específica

### Chat AI
- `POST /chat-ai` - Enviar mensaje al chatbot

## Modelos de Datos

### User
- email (unique)
- first_name, last_name
- telefono
- status (ACTIVE/INACTIVE)
- password (hash)

### Role
- name (unique)
- description
- Relación: many-to-many con Permission

### Permission
- key (unique) - ej: "user.read", "product.create"
- description

### Producto
- nombre, descripcion
- precio
- stock_actual, stock_minimo
- image_url, image_key
- marca, categoria, unidad (FK)

### Orden
- user (FK)
- total
- estado (PENDIENTE, PAGADA, ENVIADA, ENTREGADA, CANCELADA)
- items (OrdenItem[])

### Lote
- producto (FK)
- codigo
- cantidad
- fecha_venc

### Alert
- type (STOCK_BAJO, VENCIMIENTO)
- severity (INFO, WARNING, CRITICAL)
- producto, lote (FK)
- mensaje
- leida (boolean)

### Bitacora
- user (FK)
- ip
- acciones
- estado (EXITOSO, FALLIDO)
- created_at

## Sistema de Autenticación

El backend utiliza autenticación basada en cookies:

1. El usuario envía credenciales a `/auth/login`
2. El servidor valida y crea un token firmado
3. El token se envía como cookie `access_token`
4. Las peticiones subsecuentes incluyen la cookie automáticamente
5. El middleware `AuthMiddleware` valida el token en cada request

## Permisos por Rol

### ADMIN
- Todos los permisos

### VENDEDOR
- Lectura de usuarios
- CRUD de productos e inventario
- Lectura y creación de órdenes
- Lectura de alertas y reportes

### CLIENTE
- Lectura de productos
- Creación y lectura de sus propias órdenes

## CORS y Seguridad

- CORS configurado para permitir el frontend en `localhost:3000`
- Cookies con `httponly=True` para seguridad
- `samesite='Lax'` para protección CSRF
- Validación de tokens firmados con timeout de 7 días

## Base de Datos

El proyecto está configurado para usar PostgreSQL en Railway:
- Host: hopper.proxy.rlwy.net
- Puerto: 33064
- Base de datos: railway

## Comandos Útiles

### Crear superusuario (alternativa)
```bash
python manage.py createsuperuser
```

### Acceder al shell de Django
```bash
python manage.py shell
```

### Ver todas las rutas
```bash
python manage.py show_urls  # (requiere django-extensions)
```

### Limpiar base de datos y reiniciar
```bash
python manage.py flush
python init_data.py
```

## Desarrollo

Para desarrollo local, puedes usar SQLite cambiando en `.env`:
```env
DATABASE_URL=sqlite:///db.sqlite3
```

## Integración con Frontend

El backend está diseñado para trabajar con el frontend Next.js en `FrontedSI2Examen2`:

1. El frontend debe estar en `http://localhost:3000`
2. El backend corre en `http://localhost:8000`
3. El frontend hace proxy de las peticiones a través de sus routes en `/app/api/*`
4. Las cookies se comparten entre ambos en desarrollo

## Notas Importantes

- Las contraseñas se almacenan con hash usando el sistema de Django
- Los tokens de autenticación están firmados y tienen expiración
- Todas las fechas se almacenan en UTC
- Los precios usan DecimalField para precisión
- La bitácora registra automáticamente los logins

## Solución de Problemas

### Error de conexión a la base de datos
Verifica que la `DATABASE_URL` en `.env` sea correcta y que la base de datos esté accesible.

### Error de CORS
Asegúrate de que el origen del frontend esté en `CORS_ALLOWED_ORIGINS` en `.env`.

### Error de cookies
Verifica que el frontend y backend estén en el mismo dominio o configura las cookies correctamente.

## Contacto y Soporte

Para dudas o problemas, revisa la documentación de Django REST Framework:
https://www.django-rest-framework.org/

## Licencia

Este proyecto fue desarrollado como parte de un examen académico.
