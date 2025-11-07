from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from decimal import Decimal


# ============== USER MANAGEMENT ==============

class UserStatus(models.TextChoices):
    ACTIVE = 'ACTIVE', 'Active'
    INACTIVE = 'INACTIVE', 'Inactive'


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email field is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('status', UserStatus.ACTIVE)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    telefono = models.CharField(max_length=20, null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=UserStatus.choices,
        default=UserStatus.ACTIVE
    )
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        db_table = 'user'

    def __str__(self):
        return self.email


class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'role'

    def __str__(self):
        return self.name


class Permission(models.Model):
    key = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'permission'

    def __str__(self):
        return self.key


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_users')

    class Meta:
        db_table = 'user_role'
        unique_together = ('user', 'role')

    def __str__(self):
        return f"{self.user.email} - {self.role.name}"


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='permission_roles')

    class Meta:
        db_table = 'role_permission'
        unique_together = ('role', 'permission')

    def __str__(self):
        return f"{self.role.name} - {self.permission.key}"


# ============== PRODUCT CATALOG ==============

class Marca(models.Model):
    nombre = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'marca'

    def __str__(self):
        return self.nombre


class Categoria(models.Model):
    nombre = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'categoria'

    def __str__(self):
        return self.nombre


class Unidad(models.Model):
    codigo = models.CharField(max_length=50, unique=True)
    nombre = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'unidad'

    def __str__(self):
        return f"{self.codigo} - {self.nombre}"


class Producto(models.Model):
    nombre = models.CharField(max_length=255)
    descripcion = models.TextField(null=True, blank=True)
    precio = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    stock_minimo = models.IntegerField(default=0)
    stock_actual = models.IntegerField(default=0)
    activo = models.BooleanField(default=True)
    image_key = models.CharField(max_length=500, null=True, blank=True)
    image_url = models.URLField(max_length=1000, null=True, blank=True)
    creado_en = models.DateTimeField(auto_now_add=True)
    actualizado_en = models.DateTimeField(auto_now=True)

    marca = models.ForeignKey(Marca, on_delete=models.PROTECT, related_name='productos')
    categoria = models.ForeignKey(Categoria, on_delete=models.PROTECT, related_name='productos')
    unidad = models.ForeignKey(Unidad, on_delete=models.PROTECT, related_name='productos')

    class Meta:
        db_table = 'producto'

    def __str__(self):
        return self.nombre


# ============== CLIENT ==============

class Cliente(models.Model):
    nombre = models.CharField(max_length=255)
    apellido = models.CharField(max_length=255, null=True, blank=True)
    nit = models.CharField(max_length=50, unique=True, null=True, blank=True)
    telefono = models.CharField(max_length=20, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    direccion = models.TextField(null=True, blank=True)
    activo = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'cliente'

    def __str__(self):
        return f"{self.nombre} {self.apellido or ''}".strip()


# ============== SHOPPING CART ==============

class CarritoItem(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='carrito_items')
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE, related_name='carrito_items')
    cantidad = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'carrito_item'
        unique_together = ('user', 'producto')

    def __str__(self):
        return f"{self.user.email} - {self.producto.nombre} ({self.cantidad})"


# ============== ORDERS ==============

class EstadoOrden(models.TextChoices):
    PENDIENTE = 'PENDIENTE', 'Pendiente'
    PAGADA = 'PAGADA', 'Pagada'
    ENVIADA = 'ENVIADA', 'Enviada'
    ENTREGADA = 'ENTREGADA', 'Entregada'
    CANCELADA = 'CANCELADA', 'Cancelada'


class Orden(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ordenes')
    total = models.DecimalField(max_digits=10, decimal_places=2)
    estado = models.CharField(
        max_length=20,
        choices=EstadoOrden.choices,
        default=EstadoOrden.PENDIENTE
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'orden'
        ordering = ['-created_at']

    def __str__(self):
        return f"Orden #{self.id} - {self.user.email}"


class OrdenItem(models.Model):
    orden = models.ForeignKey(Orden, on_delete=models.CASCADE, related_name='items')
    producto = models.ForeignKey(Producto, on_delete=models.PROTECT, related_name='orden_items')
    cantidad = models.IntegerField()
    precio_unitario = models.DecimalField(max_digits=10, decimal_places=2)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        db_table = 'orden_item'

    def __str__(self):
        return f"Orden #{self.orden.id} - {self.producto.nombre}"


# ============== INVENTORY BATCHES ==============

class Lote(models.Model):
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE, related_name='lotes')
    codigo = models.CharField(max_length=255, null=True, blank=True)
    cantidad = models.IntegerField(default=0)
    fecha_venc = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'lote'
        indexes = [
            models.Index(fields=['producto']),
            models.Index(fields=['fecha_venc']),
        ]

    def __str__(self):
        return f"Lote {self.codigo or self.id} - {self.producto.nombre}"


# ============== ALERTS ==============

class AlertType(models.TextChoices):
    STOCK_BAJO = 'STOCK_BAJO', 'Stock Bajo'
    VENCIMIENTO = 'VENCIMIENTO', 'Vencimiento'


class AlertSeverity(models.TextChoices):
    INFO = 'INFO', 'Info'
    WARNING = 'WARNING', 'Warning'
    CRITICAL = 'CRITICAL', 'Critical'


class Alert(models.Model):
    type = models.CharField(max_length=20, choices=AlertType.choices)
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE, related_name='alerts')
    lote = models.ForeignKey(Lote, on_delete=models.CASCADE, related_name='alerts', null=True, blank=True)
    mensaje = models.TextField()
    severity = models.CharField(max_length=20, choices=AlertSeverity.choices)
    vence_en_dias = models.IntegerField(null=True, blank=True)
    stock_actual = models.IntegerField(null=True, blank=True)
    stock_minimo = models.IntegerField(null=True, blank=True)
    window_dias = models.IntegerField()
    leida = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'alert'
        indexes = [
            models.Index(fields=['type', 'leida']),
            models.Index(fields=['producto']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.type} - {self.producto.nombre}"


# ============== AUDIT LOG ==============

class EstadoBitacora(models.TextChoices):
    EXITOSO = 'EXITOSO', 'Exitoso'
    FALLIDO = 'FALLIDO', 'Fallido'


class Bitacora(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bitacoras')
    ip = models.GenericIPAddressField()
    acciones = models.TextField()
    estado = models.CharField(max_length=20, choices=EstadoBitacora.choices)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'bitacora'
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['estado', 'created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.email} - {self.acciones} ({self.estado})"


# ============== PAYMENTS ==============

class Pago(models.Model):
    orden = models.OneToOneField(Orden, on_delete=models.CASCADE, related_name='pago')
    stripe_id = models.CharField(max_length=255, unique=True)
    monto = models.FloatField()
    estado = models.CharField(max_length=100)
    metodo = models.CharField(max_length=100, null=True, blank=True)
    factura_url = models.URLField(max_length=1000, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pago'

    def __str__(self):
        return f"Pago #{self.id} - Orden #{self.orden.id}"
