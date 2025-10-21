from django.contrib import admin
from .models import (
    User, Role, Permission, UserRole, RolePermission,
    Marca, Categoria, Unidad, Producto, Cliente,
    CarritoItem, Orden, OrdenItem, Lote, Alert,
    Bitacora, Pago
)

# Register your models here.
admin.site.register(User)
admin.site.register(Role)
admin.site.register(Permission)
admin.site.register(UserRole)
admin.site.register(RolePermission)
admin.site.register(Marca)
admin.site.register(Categoria)
admin.site.register(Unidad)
admin.site.register(Producto)
admin.site.register(Cliente)
admin.site.register(CarritoItem)
admin.site.register(Orden)
admin.site.register(OrdenItem)
admin.site.register(Lote)
admin.site.register(Alert)
admin.site.register(Bitacora)
admin.site.register(Pago)
