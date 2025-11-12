from rest_framework import serializers
from .models import (
    User, Role, Permission, UserRole, RolePermission,
    Marca, Categoria, Unidad, Producto, Cliente,
    CarritoItem, Orden, OrdenItem, Lote, Alert,
    Bitacora, Pago, ModelMetrics, SalesPrediction
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
            # Frontend expects: [{ permission: { id, key, description } }]
            return [
                {'permission': PermissionSerializer(rp.permission).data}
                for rp in role_perms
            ]
        return []


class UserRoleSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(source='role.name', read_only=True)

    class Meta:
        model = UserRole
        fields = ['role_id', 'role_name']


class UserSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    password = serializers.CharField(write_only=True, required=False)

    # CamelCase fields for frontend (read and write)
    firstName = serializers.CharField(source='first_name', required=False)
    lastName = serializers.CharField(source='last_name', required=False)
    createdAt = serializers.DateTimeField(source='created_at', read_only=True)
    updatedAt = serializers.DateTimeField(source='updated_at', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'firstName', 'lastName', 'telefono',
                  'status', 'createdAt', 'updatedAt', 'roles', 'role', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def get_roles(self, obj):
        user_roles = UserRole.objects.filter(user=obj).select_related('role')
        return [ur.role.name for ur in user_roles]

    def get_role(self, obj):
        """Return first role as object for frontend compatibility"""
        user_role = UserRole.objects.filter(user=obj).select_related('role').first()
        if user_role and user_role.role:
            return {
                'id': user_role.role.id,
                'name': user_role.role.name,
                'description': user_role.role.description
            }
        return None

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
    firstName = serializers.CharField(source='first_name', read_only=True)
    lastName = serializers.CharField(source='last_name', read_only=True)
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'firstName', 'lastName', 'permissions']

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
    unidad = UnidadSerializer(read_only=True)

    # CamelCase fields for frontend
    imageUrl = serializers.CharField(source='image_url', read_only=True)
    imageKey = serializers.CharField(source='image_key', read_only=True)
    stockActual = serializers.IntegerField(source='stock_actual', read_only=True)
    stockMinimo = serializers.IntegerField(source='stock_minimo', read_only=True)
    requiereReceta = serializers.BooleanField(source='requiere_receta', read_only=True)
    creadoEn = serializers.DateTimeField(source='creado_en', read_only=True)
    actualizadoEn = serializers.DateTimeField(source='actualizado_en', read_only=True)

    class Meta:
        model = Producto
        fields = ['id', 'nombre', 'descripcion', 'precio', 'imageUrl',
                  'imageKey', 'marca', 'categoria', 'unidad', 'stockActual',
                  'stockMinimo', 'activo', 'requiereReceta', 'creadoEn', 'actualizadoEn']


class ProductoDetailSerializer(serializers.ModelSerializer):
    marca = MarcaSerializer(read_only=True)
    categoria = CategoriaSerializer(read_only=True)
    unidad = UnidadSerializer(read_only=True)

    # Accept both snake_case and camelCase for compatibility
    marca_id = serializers.IntegerField(write_only=True, required=False)
    categoria_id = serializers.IntegerField(write_only=True, required=False)
    unidad_id = serializers.IntegerField(write_only=True, required=False)

    marcaId = serializers.IntegerField(write_only=True, required=False, source='marca_id')
    categoriaId = serializers.IntegerField(write_only=True, required=False, source='categoria_id')
    unidadId = serializers.IntegerField(write_only=True, required=False, source='unidad_id')
    stockMinimo = serializers.IntegerField(write_only=True, required=False, source='stock_minimo')
    requiereReceta = serializers.BooleanField(write_only=True, required=False, source='requiere_receta')
    imageUrl = serializers.CharField(write_only=True, required=False, allow_blank=True, source='image_url')
    imageKey = serializers.CharField(write_only=True, required=False, allow_blank=True, source='image_key')

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
    productoId = serializers.IntegerField(source='producto.id', read_only=True)
    precioUnitario = serializers.FloatField(source='precio_unitario', read_only=True)
    subtotal = serializers.FloatField(read_only=True)
    producto = serializers.SerializerMethodField()

    class Meta:
        model = OrdenItem
        fields = ['id', 'productoId', 'cantidad', 'precioUnitario', 'subtotal', 'producto']

    def get_producto(self, obj):
        """Return producto in NestJS format"""
        if obj.producto:
            return {
                'id': obj.producto.id,
                'nombre': obj.producto.nombre,
                'imageUrl': obj.producto.image_url
            }
        return None


class OrdenSerializer(serializers.ModelSerializer):
    total = serializers.FloatField(read_only=True)
    createdAt = serializers.DateTimeField(source='created_at', read_only=True)
    updatedAt = serializers.DateTimeField(source='updated_at', read_only=True)
    user = serializers.SerializerMethodField()
    items = OrdenItemSerializer(many=True, read_only=True)
    pago = serializers.SerializerMethodField()

    # Campos adicionales para la vista de facturas del admin
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()

    class Meta:
        model = Orden
        fields = ['id', 'estado', 'total', 'createdAt', 'updatedAt', 'user', 'user_id',
                  'user_email', 'user_name', 'items', 'pago']

    def get_user(self, obj):
        """Return user in NestJS format"""
        return {
            'id': obj.user.id,
            'firstName': obj.user.first_name,
            'lastName': obj.user.last_name,
            'email': obj.user.email
        }

    def get_user_name(self, obj):
        """Return full name of the user"""
        return f"{obj.user.first_name} {obj.user.last_name}"

    def get_pago(self, obj):
        """Return pago in NestJS format (OneToOne relationship)"""
        try:
            if hasattr(obj, 'pago') and obj.pago:
                pago = obj.pago
                return {
                    'id': pago.id,
                    'estado': pago.estado,
                    'monto': float(pago.monto),
                    'metodo': pago.metodo,
                    'facturaUrl': pago.factura_url,
                    'createdAt': pago.created_at
                }
        except Exception:
            pass
        return None


# ============== INVENTORY SERIALIZERS ==============

class LoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lote
        fields = ['id', 'producto_id', 'codigo', 'cantidad', 'fecha_venc',
                  'created_at', 'updated_at']


# ============== ALERT SERIALIZERS ==============

class AlertSerializer(serializers.ModelSerializer):
    createdAt = serializers.DateTimeField(source='created_at', read_only=True)
    resolvedAt = serializers.DateTimeField(source='resolved_at', read_only=True, allow_null=True)
    venceEnDias = serializers.IntegerField(source='vence_en_dias', read_only=True, allow_null=True)
    stockActual = serializers.IntegerField(source='stock_actual', read_only=True, allow_null=True)
    stockMinimo = serializers.IntegerField(source='stock_minimo', read_only=True, allow_null=True)
    windowDias = serializers.IntegerField(source='window_dias', read_only=True)
    producto = serializers.SerializerMethodField()
    lote = serializers.SerializerMethodField()

    class Meta:
        model = Alert
        fields = ['id', 'type', 'severity', 'mensaje', 'venceEnDias', 'stockActual',
                  'stockMinimo', 'windowDias', 'leida', 'createdAt', 'resolvedAt',
                  'producto', 'lote']

    def get_producto(self, obj):
        """Return producto with nested relationships"""
        if not obj.producto:
            return None

        producto = obj.producto
        return {
            'id': producto.id,
            'nombre': producto.nombre,
            'marca': producto.marca.nombre if producto.marca else None,
            'categoria': producto.categoria.nombre if producto.categoria else None,
            'stockActual': producto.stock_actual,
            'stockMinimo': producto.stock_minimo,
        }

    def get_lote(self, obj):
        """Return lote info if exists"""
        if not obj.lote:
            return None

        return {
            'id': obj.lote.id,
            'codigo': obj.lote.codigo,
            'cantidad': obj.lote.cantidad,
            'fechaVenc': obj.lote.fecha_venc.isoformat() if obj.lote.fecha_venc else None
        }


# ============== AUDIT LOG SERIALIZERS ==============

class BitacoraSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    userId = serializers.IntegerField(source='user_id', read_only=True)
    fecha_entrada = serializers.SerializerMethodField()
    hora_entrada = serializers.SerializerMethodField()

    class Meta:
        model = Bitacora
        fields = ['id', 'userId', 'user', 'ip', 'acciones', 'estado', 'fecha_entrada', 'hora_entrada']

    def get_user(self, obj):
        if obj.user:
            return {
                'id': obj.user.id,
                'email': obj.user.email,
                'firstName': obj.user.first_name,
                'lastName': obj.user.last_name
            }
        return None

    def get_fecha_entrada(self, obj):
        # Convert UTC to Bolivia timezone (UTC-4) and return date as YYYY-MM-DD
        from datetime import timedelta
        bolivia_time = obj.created_at - timedelta(hours=4)
        return bolivia_time.strftime('%Y-%m-%d')

    def get_hora_entrada(self, obj):
        # Convert UTC to Bolivia timezone (UTC-4) and return time as HH:MM:SS
        from datetime import timedelta
        bolivia_time = obj.created_at - timedelta(hours=4)
        return bolivia_time.strftime('%H:%M:%S')


# ============== PAYMENT SERIALIZERS ==============

class PagoSerializer(serializers.ModelSerializer):
    orden = OrdenSerializer(read_only=True)

    class Meta:
        model = Pago
        fields = ['id', 'orden_id', 'orden', 'stripe_id', 'monto', 'estado',
                  'metodo', 'factura_url', 'created_at']


# ============== ANALYTICS & PREDICTIONS SERIALIZERS ==============

class ModelMetricsSerializer(serializers.ModelSerializer):
    """Serializer for ML model metrics"""
    class Meta:
        model = ModelMetrics
        fields = ['id', 'model_name', 'rmse', 'r2_score', 'mae', 'training_samples',
                  'features_used', 'trained_at', 'is_active']


class SalesPredictionSerializer(serializers.ModelSerializer):
    """Serializer for sales predictions"""
    categoria_nombre = serializers.CharField(source='categoria.nombre', read_only=True)
    producto_nombre = serializers.CharField(source='producto.nombre', read_only=True)

    class Meta:
        model = SalesPrediction
        fields = ['id', 'prediction_date', 'predicted_amount', 'predicted_quantity',
                  'categoria', 'categoria_nombre', 'producto', 'producto_nombre',
                  'actual_amount', 'actual_quantity', 'confidence_interval_lower',
                  'confidence_interval_upper', 'created_at']
