from rest_framework import serializers
from .models import (
    User, Role, Permission, UserRole, RolePermission,
    Marca, Categoria, Unidad, Producto, Cliente,
    CarritoItem, Orden, OrdenItem, Lote, Alert,
    Bitacora, Pago
)


# ============== USER & AUTH SERIALIZERS ==============

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'key', 'description']


class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'created_at', 'updated_at', 'permissions']

    def get_permissions(self, obj):
        if self.context.get('with_permissions', False):
            role_perms = RolePermission.objects.filter(role=obj).select_related('permission')
            return PermissionSerializer([rp.permission for rp in role_perms], many=True).data
        return []


class UserRoleSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(source='role.name', read_only=True)

    class Meta:
        model = UserRole
        fields = ['role_id', 'role_name']


class UserSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'telefono',
                  'status', 'created_at', 'updated_at', 'roles', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def get_roles(self, obj):
        user_roles = UserRole.objects.filter(user=obj).select_related('role')
        return [ur.role.name for ur in user_roles]

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        roles_data = self.context.get('roles', [])

        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()

        # Assign roles
        for role_name in roles_data:
            try:
                role = Role.objects.get(name=role_name)
                UserRole.objects.create(user=user, role=role)
            except Role.DoesNotExist:
                pass

        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        roles_data = self.context.get('roles', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()

        # Update roles if provided
        if roles_data is not None:
            UserRole.objects.filter(user=instance).delete()
            for role_name in roles_data:
                try:
                    role = Role.objects.get(name=role_name)
                    UserRole.objects.create(user=instance, role=role)
                except Role.DoesNotExist:
                    pass

        return instance


class MeSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'permissions']

    def get_permissions(self, obj):
        from .utils import get_user_permissions
        return get_user_permissions(obj)


# ============== PRODUCT CATALOG SERIALIZERS ==============

class MarcaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Marca
        fields = ['id', 'nombre', 'created_at', 'updated_at']


class CategoriaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Categoria
        fields = ['id', 'nombre', 'created_at', 'updated_at']


class UnidadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Unidad
        fields = ['id', 'codigo', 'nombre', 'created_at', 'updated_at']


class ProductoListSerializer(serializers.ModelSerializer):
    marca = MarcaSerializer(read_only=True)
    categoria = CategoriaSerializer(read_only=True)

    class Meta:
        model = Producto
        fields = ['id', 'nombre', 'descripcion', 'precio', 'image_url',
                  'image_key', 'marca', 'categoria', 'stock_actual', 'activo']


class ProductoDetailSerializer(serializers.ModelSerializer):
    marca = MarcaSerializer(read_only=True)
    categoria = CategoriaSerializer(read_only=True)
    unidad = UnidadSerializer(read_only=True)

    marca_id = serializers.IntegerField(write_only=True, required=False)
    categoria_id = serializers.IntegerField(write_only=True, required=False)
    unidad_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = Producto
        fields = '__all__'


# ============== CLIENT SERIALIZERS ==============

class ClienteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cliente
        fields = '__all__'


# ============== SHOPPING CART SERIALIZERS ==============

class CarritoItemSerializer(serializers.ModelSerializer):
    producto = ProductoListSerializer(read_only=True)
    producto_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = CarritoItem
        fields = ['id', 'user_id', 'producto_id', 'producto', 'cantidad',
                  'created_at', 'updated_at']
        read_only_fields = ['user_id']


# ============== ORDER SERIALIZERS ==============

class OrdenItemSerializer(serializers.ModelSerializer):
    producto = ProductoListSerializer(read_only=True)

    class Meta:
        model = OrdenItem
        fields = ['id', 'producto', 'cantidad', 'precio_unitario', 'subtotal']


class OrdenSerializer(serializers.ModelSerializer):
    items = OrdenItemSerializer(many=True, read_only=True)

    class Meta:
        model = Orden
        fields = ['id', 'user_id', 'total', 'estado', 'created_at',
                  'updated_at', 'items']
        read_only_fields = ['user_id']


# ============== INVENTORY SERIALIZERS ==============

class LoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lote
        fields = ['id', 'producto_id', 'codigo', 'cantidad', 'fecha_venc',
                  'created_at', 'updated_at']


# ============== ALERT SERIALIZERS ==============

class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ['id', 'type', 'producto_id', 'lote_id', 'mensaje', 'severity',
                  'vence_en_dias', 'stock_actual', 'stock_minimo', 'window_dias',
                  'leida', 'resolved_at', 'created_at', 'updated_at']


# ============== AUDIT LOG SERIALIZERS ==============

class BitacoraSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = Bitacora
        fields = ['id', 'user_id', 'user_email', 'ip', 'acciones', 'estado', 'created_at']


# ============== PAYMENT SERIALIZERS ==============

class PagoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pago
        fields = ['id', 'orden_id', 'stripe_id', 'monto', 'estado',
                  'metodo', 'factura_url', 'created_at']
