from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Q, Sum
from django.utils import timezone
from decimal import Decimal
from .models import (
    User, Role, Permission, UserRole, RolePermission,
    Marca, Categoria, Unidad, Producto, Cliente,
    CarritoItem, Orden, OrdenItem, Lote, Alert,
    Bitacora, Pago, EstadoBitacora, EstadoOrden
)
from .serializers import (
    UserSerializer, RoleSerializer, PermissionSerializer,
    MeSerializer, MarcaSerializer, CategoriaSerializer,
    UnidadSerializer, ProductoListSerializer, ProductoDetailSerializer,
    CarritoItemSerializer, OrdenSerializer,
    LoteSerializer, AlertSerializer, BitacoraSerializer,
    PagoSerializer
)
from .utils import create_auth_token, get_client_ip, get_user_permissions
from django.conf import settings
from datetime import datetime, timedelta
import stripe
import os

stripe.api_key = settings.STRIPE_SECRET_KEY


# ============== AUTHENTICATION ==============

@csrf_exempt
@api_view(['POST'])
def login(request):
    """Login endpoint"""
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'message': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email, is_active=True)
    except User.DoesNotExist:
        ip = get_client_ip(request)
        return Response({'message': 'Credenciales inválidas', 'ip': ip}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.check_password(password):
        ip = get_client_ip(request)
        return Response({'message': 'Credenciales inválidas', 'ip': ip}, status=status.HTTP_401_UNAUTHORIZED)

    # Create token
    token = create_auth_token(user.id)

    # Get user permissions
    permissions = get_user_permissions(user)

    # Create response
    ip = get_client_ip(request)
    response_data = {
        'user': {
            'id': user.id,
            'email': user.email,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'permissions': permissions
        },
        'ip': ip
    }

    response = Response(response_data)
    response.set_cookie(
        'access_token',
        token,
        max_age=60*60*24*7,  # 7 days
        httponly=True,
        samesite='Lax'
    )

    # Log the login
    Bitacora.objects.create(
        user=user,
        ip=ip,
        acciones='LOGIN',
        estado=EstadoBitacora.EXITOSO
    )

    return response


@api_view(['POST'])
def logout(request):
    """Logout endpoint"""
    response = Response({'message': 'Logged out successfully'})
    response.delete_cookie('access_token')
    return response


@api_view(['GET'])
def me(request):
    """Get current user info"""
    from django.contrib.auth.models import AnonymousUser

    # Debug: print what type of user we have
    print(f"DEBUG /me VIEW: request.user type = {type(request.user)}, value = {request.user}")

    # Check if user is authenticated
    if not request.user or isinstance(request.user, AnonymousUser):
        return Response({'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        serializer = MeSerializer(request.user)
        return Response(serializer.data)
    except Exception as e:
        # Log the error for debugging
        import traceback
        traceback.print_exc()
        return Response({
            'message': 'Error fetching user data',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============== PUBLIC ENDPOINTS ==============

@csrf_exempt
@api_view(['POST'])
def register(request):
    """User registration"""
    email = request.data.get('email')
    first_name = request.data.get('firstName')
    last_name = request.data.get('lastName')
    password = request.data.get('password')

    if not all([email, first_name, last_name, password]):
        return Response({'message': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({'message': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create(
        email=email,
        first_name=first_name,
        last_name=last_name
    )
    user.set_password(password)
    user.save()

    # Assign CLIENTE role by default
    try:
        cliente_role = Role.objects.get(name='CLIENTE')
        UserRole.objects.create(user=user, role=cliente_role)
    except Role.DoesNotExist:
        pass

    return Response({
        'id': user.id,
        'email': user.email,
        'firstName': user.first_name,
        'lastName': user.last_name,
        'message': 'Usuario registrado exitosamente'
    }, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def public_productos(request):
    """Get products for public view"""
    queryset = Producto.objects.filter(activo=True).select_related('marca', 'categoria')

    # Filter by category
    categoria = request.GET.get('categoria')
    if categoria:
        queryset = queryset.filter(categoria__nombre__icontains=categoria)

    # Search by name
    q = request.GET.get('q')
    if q:
        queryset = queryset.filter(nombre__icontains=q)

    # Limit
    limit = request.GET.get('limit')
    if limit:
        try:
            queryset = queryset[:int(limit)]
        except ValueError:
            pass

    serializer = ProductoListSerializer(queryset, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def public_categorias(request):
    """Get all categories"""
    categorias = Categoria.objects.all()
    serializer = CategoriaSerializer(categorias, many=True)
    return Response(serializer.data)


# ============== USERS MANAGEMENT ==============

@api_view(['GET'])
def list_users(request):
    """List all users"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


@api_view(['POST'])
def create_internal_user(request):
    """Create internal user (admin/vendedor)"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    # Handle both roleId (number) and roles (array of strings)
    role_id = request.data.get('roleId')
    roles_data = request.data.get('roles', [])

    # If roleId is provided, convert to roles array
    if role_id:
        try:
            role = Role.objects.get(id=role_id)
            roles_data = [role.name]
        except Role.DoesNotExist:
            pass

    serializer = UserSerializer(data=request.data, context={'roles': roles_data})

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PATCH', 'DELETE'])
def user_detail(request, user_id):
    """Update or delete user"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PATCH':
        # Handle both roleId (number) and roles (array of strings)
        role_id = request.data.get('roleId')
        roles_data = request.data.get('roles')

        # If roleId is provided, convert to roles array
        if role_id is not None:
            try:
                role = Role.objects.get(id=role_id)
                roles_data = [role.name]
            except Role.DoesNotExist:
                roles_data = []

        serializer = UserSerializer(user, data=request.data, partial=True, context={'roles': roles_data})

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        # Prevent self-deletion
        if user.id == request.user.id:
            return Response({'message': 'No puedes eliminar tu propio usuario'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user.delete()
            return Response({'message': 'User deleted successfully'})
        except Exception as e:
            # Log the actual error for debugging
            import traceback
            traceback.print_exc()
            return Response({'message': f'Error al eliminar usuario: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def list_clientes(request):
    """List clients (users with CLIENTE role) with pagination"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    # Get users with CLIENTE role
    try:
        cliente_role = Role.objects.get(name='CLIENTE')
        user_ids = UserRole.objects.filter(role=cliente_role).values_list('user_id', flat=True)
        queryset = User.objects.filter(id__in=user_ids).order_by('-created_at')
    except Role.DoesNotExist:
        queryset = User.objects.none()

    # Search
    q = request.GET.get('q', '')
    if q:
        queryset = queryset.filter(
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q) |
            Q(email__icontains=q) |
            Q(telefono__icontains=q)
        )

    # Filter by status
    status_filter = request.GET.get('status')
    if status_filter:
        queryset = queryset.filter(status=status_filter.upper())

    # Pagination
    page = int(request.GET.get('page', 1))
    size = int(request.GET.get('size', 10))
    total = queryset.count()
    total_pages = (total + size - 1) // size if total > 0 else 1

    start = (page - 1) * size
    end = start + size
    users = queryset[start:end]

    serializer = UserSerializer(users, many=True)

    return Response({
        'users': serializer.data,
        'total': total,
        'totalPages': total_pages,
        'page': page,
        'size': size
    })


@api_view(['GET'])
def clientes_by_date_range(request):
    """Get clients (users with CLIENTE role) by date range"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    fecha_inicial = request.GET.get('fechaInicial')
    fecha_final = request.GET.get('fechaFinal')

    # Get users with CLIENTE role
    try:
        cliente_role = Role.objects.get(name='CLIENTE')
        user_ids = UserRole.objects.filter(role=cliente_role).values_list('user_id', flat=True)
        queryset = User.objects.filter(id__in=user_ids).order_by('-created_at')
    except Role.DoesNotExist:
        queryset = User.objects.none()

    if fecha_inicial:
        queryset = queryset.filter(created_at__gte=fecha_inicial)
    if fecha_final:
        queryset = queryset.filter(created_at__lte=fecha_final)

    serializer = UserSerializer(queryset, many=True)
    return Response({'clientes': serializer.data})


# ============== ROLES & PERMISSIONS ==============

@api_view(['GET'])
def list_roles(request):
    """List all roles"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    with_perms = request.GET.get('withPerms', 'false').lower() == 'true'

    roles = Role.objects.all()
    serializer = RoleSerializer(roles, many=True, context={'with_permissions': with_perms})
    return Response(serializer.data)


@api_view(['POST'])
def create_role(request):
    """Create new role"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    serializer = RoleSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_role(request, role_id):
    """Get specific role"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        role = Role.objects.get(id=role_id)
        serializer = RoleSerializer(role, context={'with_permissions': True})
        return Response(serializer.data)
    except Role.DoesNotExist:
        return Response({'message': 'Role not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['PUT'])
def update_role(request, role_id):
    """Update role"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        role = Role.objects.get(id=role_id)
        serializer = RoleSerializer(role, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Role.DoesNotExist:
        return Response({'message': 'Role not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
def delete_role(request, role_id):
    """Delete role"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        role = Role.objects.get(id=role_id)
        role.delete()
        return Response({'message': 'Role deleted successfully'})
    except Role.DoesNotExist:
        return Response({'message': 'Role not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def get_role_permissions(request, role_id):
    """Get permissions for a role"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        role = Role.objects.get(id=role_id)
        role_perms = RolePermission.objects.filter(role=role).select_related('permission')
        permissions = [rp.permission for rp in role_perms]
        serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data)
    except Role.DoesNotExist:
        return Response({'message': 'Role not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['PUT'])
def update_role_permissions(request, role_id):
    """Update permissions for a role"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        role = Role.objects.get(id=role_id)
        # Accept both 'permissions' and 'permissionIds' for compatibility
        permission_ids = request.data.get('permissionIds') or request.data.get('permissions', [])

        # Delete existing permissions
        RolePermission.objects.filter(role=role).delete()

        # Add new permissions
        for perm_id in permission_ids:
            try:
                permission = Permission.objects.get(id=perm_id)
                RolePermission.objects.create(role=role, permission=permission)
            except Permission.DoesNotExist:
                pass

        return Response({'message': 'Permissions updated successfully'})
    except Role.DoesNotExist:
        return Response({'message': 'Role not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def list_permissions(request):
    """List all permissions"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    permissions = Permission.objects.all()
    serializer = PermissionSerializer(permissions, many=True)
    return Response(serializer.data)


# ============== SHOPPING CART ==============

@api_view(['GET'])
def get_cart(request):
    """Get user's cart items"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    items = CarritoItem.objects.filter(user=request.user).select_related('producto', 'producto__marca')
    serializer = CarritoItemSerializer(items, many=True)
    return Response(serializer.data)


@api_view(['POST'])
def add_to_cart(request):
    """Add item to cart"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    producto_id = request.data.get('productoId')
    cantidad = request.data.get('cantidad', 1)

    try:
        producto = Producto.objects.get(id=producto_id)
    except Producto.DoesNotExist:
        return Response({'message': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

    # Validar stock disponible
    if producto.stock_actual <= 0:
        return Response({'message': 'Producto sin stock disponible'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if item already exists in cart
    cart_item, created = CarritoItem.objects.get_or_create(
        user=request.user,
        producto=producto,
        defaults={'cantidad': cantidad}
    )

    if not created:
        nueva_cantidad = cart_item.cantidad + cantidad
    else:
        nueva_cantidad = cantidad

    # Validar que no exceda el stock disponible
    if nueva_cantidad > producto.stock_actual:
        return Response({
            'message': f'Stock insuficiente. Disponible: {producto.stock_actual}, solicitado: {nueva_cantidad}'
        }, status=status.HTTP_400_BAD_REQUEST)

    if not created:
        cart_item.cantidad = nueva_cantidad
        cart_item.save()

    serializer = CarritoItemSerializer(cart_item)
    return Response(serializer.data)


@api_view(['PATCH', 'DELETE'])
def update_cart_item(request, item_id):
    """Update or delete cart item"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        item = CarritoItem.objects.get(id=item_id, user=request.user)

        # DELETE: Eliminar item del carrito
        if request.method == 'DELETE':
            item.delete()
            return Response({'message': 'Item removed from cart'})

        # PATCH: Actualizar cantidad
        cantidad = request.data.get('cantidad')

        if cantidad is not None:
            # Validar que la cantidad no exceda el stock disponible
            if cantidad > item.producto.stock_actual:
                return Response({
                    'message': f'Stock insuficiente. Disponible: {item.producto.stock_actual}'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validar que la cantidad sea al menos 1
            if cantidad < 1:
                return Response({'message': 'La cantidad debe ser al menos 1'}, status=status.HTTP_400_BAD_REQUEST)

            item.cantidad = cantidad
            item.save()

        serializer = CarritoItemSerializer(item)
        return Response(serializer.data)
    except CarritoItem.DoesNotExist:
        return Response({'message': 'Cart item not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
def remove_cart_item(request, item_id):
    """Remove item from cart"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        item = CarritoItem.objects.get(id=item_id, user=request.user)
        item.delete()
        return Response({'message': 'Item removed from cart'})
    except CarritoItem.DoesNotExist:
        return Response({'message': 'Cart item not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
def clear_cart(request):
    """Clear entire cart"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    CarritoItem.objects.filter(user=request.user).delete()
    return Response({'message': 'Cart cleared'})


@api_view(['GET'])
def list_ordenes(request):
    """List all orders with advanced filters (based on NestJS pedidos service)"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from .utils import has_permission

    # Base queryset según permisos
    if has_permission(request.user, 'order.read'):
        queryset = Orden.objects.all()
    else:
        queryset = Orden.objects.filter(user=request.user)

    # Filtro por estado
    status_filter = request.GET.get('status')
    if status_filter:
        queryset = queryset.filter(estado=status_filter)

    # Filtro por rango de fechas
    from_date = request.GET.get('from')
    to_date = request.GET.get('to')
    if from_date:
        queryset = queryset.filter(created_at__gte=from_date)
    if to_date:
        queryset = queryset.filter(created_at__lte=to_date)

    # Búsqueda por texto (ID, usuario, email, producto)
    search = request.GET.get('search', '').strip()
    if search:
        # Intentar convertir a número para buscar por ID
        try:
            numeric_id = int(search)
            queryset = queryset.filter(
                Q(id=numeric_id) |
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(user__email__icontains=search) |
                Q(items__producto__nombre__icontains=search)
            ).distinct()
        except ValueError:
            # No es un número, buscar solo por texto
            queryset = queryset.filter(
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(user__email__icontains=search) |
                Q(items__producto__nombre__icontains=search)
            ).distinct()

    # Paginación
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('pageSize', 10))
    page_size = min(page_size, 100)  # Máximo 100 items por página

    total = queryset.count()
    total_pages = max(1, (total + page_size - 1) // page_size) if total > 0 else 1

    start = (page - 1) * page_size
    end = start + page_size

    # Obtener órdenes con todas las relaciones (order_by BEFORE slice)
    ordenes = queryset.select_related('user', 'pago').prefetch_related('items__producto').order_by('-created_at')[start:end]

    serializer = OrdenSerializer(ordenes, many=True)

    return Response({
        'items': serializer.data,
        'total': total,
        'page': page,
        'pageSize': page_size,
        'totalPages': total_pages
    })


@api_view(['GET'])
def get_orden(request, orden_id):
    """Get order detail with all relations (based on NestJS findOne)"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        from .utils import has_permission

        # Query con todas las relaciones cargadas
        queryset = Orden.objects.select_related('user', 'pago').prefetch_related('items__producto')

        if has_permission(request.user, 'order.read'):
            orden = queryset.get(id=orden_id)
        else:
            orden = queryset.get(id=orden_id, user=request.user)

        serializer = OrdenSerializer(orden)
        return Response(serializer.data)
    except Orden.DoesNotExist:
        return Response({'message': 'Pedido no encontrado'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['PATCH'])
def update_orden_status(request, orden_id):
    """Update order status (requires order.update permission)"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from .utils import has_permission

    # Verificar permisos
    if not has_permission(request.user, 'order.update'):
        return Response({'message': 'No tienes permisos para actualizar pedidos'},
                       status=status.HTTP_403_FORBIDDEN)

    try:
        orden = Orden.objects.select_related('user', 'pago').prefetch_related('items__producto').get(id=orden_id)
    except Orden.DoesNotExist:
        return Response({'message': 'Pedido no encontrado'}, status=status.HTTP_404_NOT_FOUND)

    # Obtener y validar el nuevo estado
    nuevo_estado = request.data.get('estado')
    if not nuevo_estado:
        return Response({'message': 'El campo estado es requerido'}, status=status.HTTP_400_BAD_REQUEST)

    # Validar que el estado sea válido
    estados_validos = [choice[0] for choice in EstadoOrden.choices]
    if nuevo_estado not in estados_validos:
        return Response({
            'message': f'Estado inválido. Debe ser uno de: {", ".join(estados_validos)}'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Actualizar el estado
    orden.estado = nuevo_estado
    orden.save()

    # Log de auditoría
    log_ok(request, f'Estado de pedido #{orden_id} actualizado a {nuevo_estado}')

    # Retornar la orden actualizada
    serializer = OrdenSerializer(orden)
    return Response(serializer.data)


@api_view(['POST'])
def checkout(request):
    """Create order from cart"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    # Get cart items
    cart_items = CarritoItem.objects.filter(user=request.user).select_related('producto')

    if not cart_items.exists():
        return Response({'message': 'Cart is empty'}, status=status.HTTP_400_BAD_REQUEST)

    # Validar stock antes de crear la orden
    for item in cart_items:
        if item.cantidad > item.producto.stock_actual:
            return Response({
                'message': f'Stock insuficiente para {item.producto.nombre}. Disponible: {item.producto.stock_actual}'
            }, status=status.HTTP_400_BAD_REQUEST)

    # Calculate total
    total = Decimal('0.00')
    for item in cart_items:
        total += item.producto.precio * item.cantidad

    # Create order
    orden = Orden.objects.create(
        user=request.user,
        total=total,
        estado=EstadoOrden.PENDIENTE
    )

    # Create order items and reduce stock
    for item in cart_items:
        OrdenItem.objects.create(
            orden=orden,
            producto=item.producto,
            cantidad=item.cantidad,
            precio_unitario=item.producto.precio,
            subtotal=item.producto.precio * item.cantidad
        )
        # Reducir stock
        item.producto.stock_actual -= item.cantidad
        item.producto.save()

    # Clear cart
    cart_items.delete()

    return Response({'id': orden.id, 'total': float(total)}, status=status.HTTP_201_CREATED)


# ============== CATEGORIES, BRANDS & UNITS ==============

@api_view(['GET', 'POST'])
def categorias(request):
    """List or create categories"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == 'GET':
        categorias = Categoria.objects.all().order_by('nombre')
        serializer = CategoriaSerializer(categorias, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = CategoriaSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def categoria_detail(request, categoria_id):
    """Get, update or delete a category"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        categoria = Categoria.objects.get(id=categoria_id)
    except Categoria.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = CategoriaSerializer(categoria)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = CategoriaSerializer(categoria, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        categoria.delete()
        return Response({'message': 'Category deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'POST'])
def marcas(request):
    """List or create brands"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == 'GET':
        marcas = Marca.objects.all().order_by('nombre')
        serializer = MarcaSerializer(marcas, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = MarcaSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def marca_detail(request, marca_id):
    """Get, update or delete a brand"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        marca = Marca.objects.get(id=marca_id)
    except Marca.DoesNotExist:
        return Response({'message': 'Brand not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = MarcaSerializer(marca)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = MarcaSerializer(marca, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        marca.delete()
        return Response({'message': 'Brand deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'POST'])
def unidades(request):
    """List or create units"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == 'GET':
        unidades = Unidad.objects.all().order_by('nombre')
        serializer = UnidadSerializer(unidades, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = UnidadSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def unidad_detail(request, unidad_id):
    """Get, update or delete a unit"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        unidad = Unidad.objects.get(id=unidad_id)
    except Unidad.DoesNotExist:
        return Response({'message': 'Unit not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = UnidadSerializer(unidad)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = UnidadSerializer(unidad, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        unidad.delete()
        return Response({'message': 'Unit deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


# ============== PRODUCTS ==============

@api_view(['GET'])
def productos_presign(request):
    """Generate presigned URL for uploading product images to S3"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from .s3_service import S3Service
    from datetime import datetime

    # Get query parameters
    filename = request.GET.get('filename', 'img.webp')
    content_type = request.GET.get('contentType', 'image/webp')

    # Sanitize filename: replace spaces with dashes and convert to lowercase
    safe_filename = filename.replace(' ', '-').lower()

    # Generate unique key with timestamp
    timestamp = int(datetime.now().timestamp() * 1000)  # milliseconds
    key = f"productos/tmp/{timestamp}-{safe_filename}"

    try:
        s3_service = S3Service()
        result = s3_service.generate_presigned_upload_url(key, content_type)
        return Response(result)
    except Exception as e:
        return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
def productos(request):
    """List or create products"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == 'GET':
        queryset = Producto.objects.all().select_related('marca', 'categoria', 'unidad').order_by('-creado_en')

        # Filter by category
        categoria_id = request.GET.get('categoria_id')
        if categoria_id:
            queryset = queryset.filter(categoria_id=categoria_id)

        # Filter by brand
        marca_id = request.GET.get('marca_id')
        if marca_id:
            queryset = queryset.filter(marca_id=marca_id)

        # Filter by active status
        activo = request.GET.get('activo')
        if activo is not None:
            queryset = queryset.filter(activo=activo.lower() == 'true')

        # Search by name
        search = request.GET.get('search')
        if search:
            queryset = queryset.filter(nombre__icontains=search)

        serializer = ProductoListSerializer(queryset, many=True)
        return Response({
            'productos': serializer.data,
            'totalPages': 1  # For now, no pagination
        })

    elif request.method == 'POST':
        serializer = ProductoDetailSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
def producto_detail(request, producto_id):
    """Get, update or delete a product"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        producto = Producto.objects.select_related('marca', 'categoria', 'unidad').get(id=producto_id)
    except Producto.DoesNotExist:
        return Response({'message': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = ProductoDetailSerializer(producto)
        return Response(serializer.data)

    elif request.method in ['PUT', 'PATCH']:
        serializer = ProductoDetailSerializer(producto, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        producto.delete()
        return Response({'message': 'Product deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


# ============== PRODUCTS & INVENTORY ==============

@api_view(['GET'])
def get_producto_lotes(request, producto_id):
    """Get batches for a product"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    lotes = Lote.objects.filter(producto_id=producto_id).order_by('-created_at')
    serializer = LoteSerializer(lotes, many=True)
    return Response(serializer.data)


@api_view(['POST'])
def create_lote(request, producto_id):
    """Create batch for product"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        producto = Producto.objects.get(id=producto_id)
    except Producto.DoesNotExist:
        return Response({'message': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

    serializer = LoteSerializer(data=request.data)
    if serializer.is_valid():
        # Pasar el producto directamente al save() para asignar la ForeignKey
        lote = serializer.save(producto=producto)

        # Actualizar stock_actual del producto sumando todos los lotes
        total_stock = Lote.objects.filter(producto=producto).aggregate(
            total=Sum('cantidad')
        )['total'] or 0
        producto.stock_actual = total_stock
        producto.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PATCH'])
def update_lote(request, lote_id):
    """Update batch"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        lote = Lote.objects.get(id=lote_id)
        producto_id = lote.producto_id
        serializer = LoteSerializer(lote, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()

            # Actualizar stock_actual del producto sumando todos los lotes
            total_stock = Lote.objects.filter(producto_id=producto_id).aggregate(
                total=Sum('cantidad')
            )['total'] or 0
            Producto.objects.filter(id=producto_id).update(stock_actual=total_stock)

            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Lote.DoesNotExist:
        return Response({'message': 'Lote not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
def delete_lote(request, lote_id):
    """Delete batch"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        lote = Lote.objects.get(id=lote_id)
        producto_id = lote.producto_id
        lote.delete()

        # Actualizar stock_actual del producto sumando todos los lotes restantes
        total_stock = Lote.objects.filter(producto_id=producto_id).aggregate(
            total=Sum('cantidad')
        )['total'] or 0
        Producto.objects.filter(id=producto_id).update(stock_actual=total_stock)

        return Response({'message': 'Lote deleted successfully'})
    except Lote.DoesNotExist:
        return Response({'message': 'Lote not found'}, status=status.HTTP_404_NOT_FOUND)


# ============== ALERTS ==============

SEVERITY_WEIGHT = {
    'CRITICAL': 3,
    'WARNING': 2,
    'INFO': 1,
}

DEFAULT_WINDOW_DAYS = int(os.environ.get('ALERT_WINDOW_DAYS', '30'))


def evaluate_stock_alert(producto):
    """Evaluate if a product needs a stock alert"""
    actual = producto.stock_actual or 0
    minimo = producto.stock_minimo or 0

    if actual <= 0:
        return {
            'severity': 'CRITICAL',
            'mensaje': 'Sin stock disponible',
            'stock_actual': actual,
            'stock_minimo': minimo
        }

    if actual <= minimo:
        return {
            'severity': 'WARNING',
            'mensaje': f'Stock bajo ({actual}/{minimo})',
            'stock_actual': actual,
            'stock_minimo': minimo
        }

    return None


def evaluate_expiry_alert(lote, window_days):
    """Evaluate if a lote needs an expiry alert"""
    if not lote.fecha_venc or lote.cantidad <= 0:
        return None

    now = datetime.now().date()
    fecha_venc = lote.fecha_venc.date() if isinstance(lote.fecha_venc, datetime) else lote.fecha_venc
    days_until = (fecha_venc - now).days

    # Solo alertar si está dentro del doble de la ventana
    if days_until > window_days * 2:
        return None

    if days_until <= 3:
        mensaje = f'Lote vencido hace {abs(days_until)} día(s)' if days_until < 0 else f'Lote vence en {days_until} día(s)'
        return {
            'severity': 'CRITICAL',
            'mensaje': mensaje,
            'days_until': days_until
        }

    if days_until <= window_days:
        return {
            'severity': 'WARNING',
            'mensaje': f'Lote vence en {days_until} día(s)',
            'days_until': days_until
        }

    if days_until <= window_days * 2:
        return {
            'severity': 'INFO',
            'mensaje': f'Lote vence en {days_until} día(s)',
            'days_until': days_until
        }

    return None


def sync_stock_alerts():
    """Synchronize stock alerts for all products"""
    from django.utils import timezone

    productos = Producto.objects.all().select_related('marca', 'categoria')
    active_alerts = Alert.objects.filter(type='STOCK_BAJO', resolved_at__isnull=True).select_related('producto')

    # Map de alertas activas por producto_id
    active_map = {alert.producto_id: alert for alert in active_alerts}

    created_count = 0
    updated_count = 0
    resolved_count = 0
    seen_products = set()

    for producto in productos:
        seen_products.add(producto.id)
        evaluation = evaluate_stock_alert(producto)
        existing = active_map.get(producto.id)

        # Si no necesita alerta pero existe una activa, resolverla
        if not evaluation:
            if existing:
                existing.resolved_at = timezone.now()
                existing.save()
                resolved_count += 1
            continue

        # Si no existe, crearla
        if not existing:
            Alert.objects.create(
                type='STOCK_BAJO',
                producto=producto,
                mensaje=evaluation['mensaje'],
                severity=evaluation['severity'],
                stock_actual=evaluation['stock_actual'],
                stock_minimo=evaluation['stock_minimo'],
                window_dias=DEFAULT_WINDOW_DAYS
            )
            created_count += 1
            continue

        # Si existe, verificar si necesita actualizarse
        severity_changed = existing.severity != evaluation['severity']
        message_changed = existing.mensaje != evaluation['mensaje']
        stock_changed = (existing.stock_actual != evaluation['stock_actual'] or
                        existing.stock_minimo != evaluation['stock_minimo'])

        if severity_changed or message_changed or stock_changed:
            existing.severity = evaluation['severity']
            existing.mensaje = evaluation['mensaje']
            existing.stock_actual = evaluation['stock_actual']
            existing.stock_minimo = evaluation['stock_minimo']

            # Si la severidad aumentó, marcar como no leída
            if severity_changed and SEVERITY_WEIGHT[evaluation['severity']] > SEVERITY_WEIGHT[existing.severity]:
                existing.leida = False

            existing.save()
            updated_count += 1

    # Resolver alertas de productos que ya no existen
    for alert in active_alerts:
        if alert.producto_id not in seen_products:
            alert.resolved_at = timezone.now()
            alert.save()
            resolved_count += 1

    return {'created': created_count, 'updated': updated_count, 'resolved': resolved_count}


def sync_expiry_alerts(window_days=None):
    """Synchronize expiry alerts for all lotes"""
    from django.utils import timezone

    if window_days is None:
        window_days = DEFAULT_WINDOW_DAYS

    now = datetime.now().date()
    max_date = now + timedelta(days=window_days * 2)

    lotes = Lote.objects.filter(
        fecha_venc__lte=max_date
    ).select_related('producto', 'producto__marca', 'producto__categoria')

    active_alerts = Alert.objects.filter(type='VENCIMIENTO', resolved_at__isnull=True).select_related('producto', 'lote')

    # Map de alertas activas por lote_id
    active_map = {alert.lote_id: alert for alert in active_alerts if alert.lote_id}

    created_count = 0
    updated_count = 0
    resolved_count = 0
    seen_lotes = set()

    for lote in lotes:
        seen_lotes.add(lote.id)
        evaluation = evaluate_expiry_alert(lote, window_days)
        existing = active_map.get(lote.id)

        # Si no necesita alerta pero existe una activa, resolverla
        if not evaluation:
            if existing:
                existing.resolved_at = timezone.now()
                existing.save()
                resolved_count += 1
            continue

        # Si no existe, crearla
        if not existing:
            Alert.objects.create(
                type='VENCIMIENTO',
                producto=lote.producto,
                lote=lote,
                mensaje=evaluation['mensaje'],
                severity=evaluation['severity'],
                vence_en_dias=evaluation['days_until'],
                stock_actual=lote.producto.stock_actual,
                stock_minimo=lote.producto.stock_minimo,
                window_dias=window_days
            )
            created_count += 1
            continue

        # Si existe, verificar si necesita actualizarse
        severity_changed = existing.severity != evaluation['severity']
        message_changed = existing.mensaje != evaluation['mensaje']
        days_changed = existing.vence_en_dias != evaluation['days_until']

        if severity_changed or message_changed or days_changed:
            existing.severity = evaluation['severity']
            existing.mensaje = evaluation['mensaje']
            existing.vence_en_dias = evaluation['days_until']

            # Si la severidad aumentó, marcar como no leída
            if severity_changed and SEVERITY_WEIGHT[evaluation['severity']] > SEVERITY_WEIGHT[existing.severity]:
                existing.leida = False

            existing.save()
            updated_count += 1

    # Resolver alertas de lotes que ya no existen o no tienen fecha_venc
    for alert in active_alerts:
        if alert.lote_id and alert.lote_id not in seen_lotes:
            alert.resolved_at = timezone.now()
            alert.save()
            resolved_count += 1

    return {'created': created_count, 'updated': updated_count, 'resolved': resolved_count}


@api_view(['GET'])
def list_alerts(request):
    """Get all alerts with advanced filters and pagination"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from .utils import has_permission

    if not has_permission(request.user, 'alert.read'):
        return Response({'message': 'No tienes permisos para ver alertas'},
                       status=status.HTTP_403_FORBIDDEN)

    # Sincronizar alertas antes de listar
    window_days = int(request.GET.get('windowDays', DEFAULT_WINDOW_DAYS))
    sync_stock_alerts()
    sync_expiry_alerts(window_days)

    # Filtros
    queryset = Alert.objects.filter(resolved_at__isnull=True)

    # Filtro por tipo
    alert_type = request.GET.get('type')
    if alert_type == 'stock':
        queryset = queryset.filter(type='STOCK_BAJO')
    elif alert_type == 'expiry':
        queryset = queryset.filter(type='VENCIMIENTO')

    # Filtro por severidad
    severity = request.GET.get('severity')
    if severity and severity.upper() in ['INFO', 'WARNING', 'CRITICAL']:
        queryset = queryset.filter(severity=severity.upper())

    # Filtro solo no leídas
    unread_only = request.GET.get('unreadOnly', '').lower() == 'true'
    if unread_only:
        queryset = queryset.filter(leida=False)

    # Búsqueda por texto
    search = request.GET.get('search', '').strip()
    if search:
        queryset = queryset.filter(
            Q(producto__nombre__icontains=search) |
            Q(producto__categoria__nombre__icontains=search) |
            Q(producto__marca__nombre__icontains=search)
        )

    # Filtrar alertas de vencimiento dentro de la ventana
    if alert_type != 'stock':
        queryset = queryset.filter(
            Q(type='STOCK_BAJO') |
            Q(type='VENCIMIENTO', vence_en_dias__lte=window_days * 2)
        )

    # Contar no leídas
    unread_count = queryset.filter(leida=False).count()

    # Paginación
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('pageSize', 20))
    page_size = min(page_size, 100)  # Máximo 100 items por página

    # Ordenamiento
    queryset = queryset.order_by(
        '-severity',  # CRITICAL, WARNING, INFO
        'vence_en_dias',  # Más cercanos primero
        'stock_actual',  # Menor stock primero
        '-created_at'
    )

    # Total antes de paginar
    total = queryset.count()
    total_pages = max(1, (total + page_size - 1) // page_size) if total > 0 else 1

    # Aplicar paginación
    start = (page - 1) * page_size
    end = start + page_size

    # Obtener alertas con relaciones
    alerts = queryset.select_related(
        'producto',
        'producto__marca',
        'producto__categoria',
        'lote'
    )[start:end]

    serializer = AlertSerializer(alerts, many=True)

    return Response({
        'data': serializer.data,
        'meta': {
            'total': total,
            'page': page,
            'pageSize': page_size,
            'totalPages': total_pages,
            'unread': unread_count
        }
    })


@api_view(['PATCH'])
def mark_alert_read(request, alert_id):
    """Mark alert as read"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from .utils import has_permission

    if not has_permission(request.user, 'alert.update'):
        return Response({'message': 'No tienes permisos para actualizar alertas'},
                       status=status.HTTP_403_FORBIDDEN)

    try:
        alert = Alert.objects.select_related(
            'producto',
            'producto__marca',
            'producto__categoria',
            'lote'
        ).get(id=alert_id, resolved_at__isnull=True)

        if alert.leida:
            # Ya está leída, solo devolver
            serializer = AlertSerializer(alert)
            return Response(serializer.data)

        alert.leida = True
        alert.save()
        serializer = AlertSerializer(alert)
        return Response(serializer.data)
    except Alert.DoesNotExist:
        return Response({'message': 'Alerta no encontrada'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['PATCH'])
def mark_all_alerts_read(request):
    """Mark all alerts as read"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from .utils import has_permission

    if not has_permission(request.user, 'alert.update'):
        return Response({'message': 'No tienes permisos para actualizar alertas'},
                       status=status.HTTP_403_FORBIDDEN)

    # Filtro opcional por tipo
    alert_type = request.GET.get('type')
    queryset = Alert.objects.filter(leida=False, resolved_at__isnull=True)

    if alert_type == 'stock':
        queryset = queryset.filter(type='STOCK_BAJO')
    elif alert_type == 'expiry':
        queryset = queryset.filter(type='VENCIMIENTO')

    updated_count = queryset.update(leida=True)
    return Response({'updated': updated_count})


# ============== AUDIT LOG ==============

@csrf_exempt
@api_view(['POST'])
def create_bitacora(request):
    """Create audit log entry"""
    user_id = request.data.get('userId', 0)
    ip = request.data.get('ip') or get_client_ip(request)
    acciones = request.data.get('acciones', '')
    estado_str = request.data.get('estado', 'EXITOSO')

    # Handle userId = 0 (anonymous user)
    if user_id == 0:
        if not request.user:
            return Response({'message': 'User required'}, status=status.HTTP_400_BAD_REQUEST)
        user = request.user
    else:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    bitacora = Bitacora.objects.create(
        user=user,
        ip=ip,
        acciones=acciones,
        estado=estado_str
    )

    serializer = BitacoraSerializer(bitacora)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def list_bitacora(request):
    """Get audit logs with advanced filters"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from django.db.models import Q

    queryset = Bitacora.objects.all().select_related('user').order_by('-id')

    # Filter by userId
    user_id = request.GET.get('userId')
    if user_id:
        queryset = queryset.filter(user_id=user_id)

    # Filter by estado
    estado = request.GET.get('estado')
    if estado:
        queryset = queryset.filter(estado=estado)

    # Filter by nombre (search in firstName, lastName, email)
    nombre = request.GET.get('nombre', '').strip()
    if nombre:
        queryset = queryset.filter(
            Q(user__first_name__icontains=nombre) |
            Q(user__last_name__icontains=nombre) |
            Q(user__email__icontains=nombre)
        )

    # Filter by date range (desde/hasta are in ISO format with timezone)
    desde = request.GET.get('desde')
    if desde:
        queryset = queryset.filter(created_at__gte=desde)

    hasta = request.GET.get('hasta')
    if hasta:
        queryset = queryset.filter(created_at__lte=hasta)

    # Pagination
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('pageSize', request.GET.get('perPage', 20)))

    # Limit page_size to max 100
    page_size = min(page_size, 100)

    total = queryset.count()
    start = (page - 1) * page_size
    end = start + page_size

    logs = queryset[start:end]
    serializer = BitacoraSerializer(logs, many=True)

    return Response({
        'items': serializer.data,
        'total': total,
        'page': page,
        'pageSize': page_size
    })


# ============== PAYMENTS ==============

@api_view(['POST'])
def create_pago(request):
    """Create Stripe payment session"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    orden_id = request.data.get('ordenId')
    monto = request.data.get('monto')
    moneda = request.data.get('moneda', 'usd')

    # Allow custom success/cancel URLs (useful for mobile)
    custom_success_url = request.data.get('successUrl')
    custom_cancel_url = request.data.get('cancelUrl')

    try:
        orden = Orden.objects.get(id=orden_id, user=request.user)
    except Orden.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    # Create Stripe checkout session
    try:
        # Always use production frontend URL for redirects
        frontend_url = os.getenv('FRONTEND_URL', 'https://si-2-examen-2.vercel.app')

        # Use custom URLs if provided, otherwise use production frontend URL
        success_url = custom_success_url if custom_success_url else f'{frontend_url}/success?session_id={{CHECKOUT_SESSION_ID}}'
        cancel_url = custom_cancel_url if custom_cancel_url else f'{frontend_url}/cancel'

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': moneda,
                    'product_data': {
                        'name': f'Orden #{orden_id}',
                    },
                    'unit_amount': int(monto * 100),  # Convert to cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=success_url,
            cancel_url=cancel_url,
        )

        # Save payment info
        pago = Pago.objects.create(
            orden=orden,
            stripe_id=checkout_session.id,
            monto=monto,
            estado='pending',
            metodo='stripe'
        )

        return Response({'url': checkout_session.url})
    except Exception as e:
        return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def confirm_pago(request):
    """Confirm payment"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    session_id = request.data.get('sessionId')

    try:
        pago = Pago.objects.get(stripe_id=session_id)
        pago.estado = 'completed'
        pago.save()

        # Update order status
        pago.orden.estado = EstadoOrden.PAGADA
        pago.orden.save()

        # Registrar venta en bitácora
        ip = get_client_ip(request)
        Bitacora.objects.create(
            user=request.user,
            ip=ip,
            acciones=f'Venta confirmada - Orden #{pago.orden.id} - Monto: ${pago.monto}',
            estado=EstadoBitacora.EXITOSO
        )

        return Response({'message': 'Payment confirmed'})
    except Pago.DoesNotExist:
        return Response({'message': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def list_pagos(request):
    """Get all payments/invoices (admin only - shows all customers)"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    # Si el usuario tiene permiso admin, mostrar todos los pagos
    # Sino, solo mostrar sus propios pagos
    from .utils import has_permission
    if has_permission(request.user, 'order.read'):
        pagos = Pago.objects.all().select_related('orden', 'orden__user').order_by('-created_at')
    else:
        pagos = Pago.objects.filter(orden__user=request.user).select_related('orden').order_by('-created_at')

    serializer = PagoSerializer(pagos, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def my_pagos(request):
    """Get current user's payments/invoices only (always filtered by current user)"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    # Siempre filtrar por el usuario actual, sin importar permisos
    pagos = Pago.objects.filter(orden__user=request.user).select_related('orden').order_by('-created_at')
    serializer = PagoSerializer(pagos, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def get_pago(request, pago_id):
    """Get specific payment/invoice"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        from .utils import has_permission

        # Si es admin, puede ver cualquier factura
        if has_permission(request.user, 'order.read'):
            pago = Pago.objects.get(id=pago_id)
        else:
            # Si no es admin, solo puede ver sus propias facturas
            pago = Pago.objects.get(id=pago_id, orden__user=request.user)

        serializer = PagoSerializer(pago)
        return Response(serializer.data)
    except Pago.DoesNotExist:
        return Response({'message': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)


# ============== CHAT AI ==============

@api_view(['POST'])
def chat_ai(request):
    """Chat AI endpoint using Gemini"""
    # Note: This endpoint is public, no authentication required
    # if not request.user:
    #     return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    message = request.data.get('message', '')

    if not message:
        return Response({'message': 'El mensaje es requerido'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        from .gemini_service import GeminiService, ProductoSimplificado

        # Get all active products
        productos = Producto.objects.filter(activo=True).select_related('marca', 'categoria')

        # Convert to simplified format
        productos_simplificados = [
            ProductoSimplificado(
                id=p.id,
                nombre=p.nombre,
                descripcion=p.descripcion or '',
                precio=float(p.precio),
                marca=p.marca.nombre,
                categoria=p.categoria.nombre
            )
            for p in productos
        ]

        # Process with Gemini
        gemini_service = GeminiService()
        result = gemini_service.chat(message, productos_simplificados)

        return Response(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({
            'message': 'Error al procesar el mensaje',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def voice_assistant(request):
    """Voice assistant endpoint for generating reports"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    from .utils import has_permission

    # Check permissions
    if not has_permission(request.user, 'user.read'):
        return Response({'message': 'No tienes permisos para usar el asistente de voz'},
                       status=status.HTTP_403_FORBIDDEN)

    command = request.data.get('command', '').strip()
    audio = request.data.get('audio')
    mime_type = request.data.get('mimeType')

    if not command and not (audio and mime_type):
        return Response({'message': 'Debe proporcionar un comando de texto o audio'},
                       status=status.HTTP_400_BAD_REQUEST)

    try:
        # Import voice assistant functions
        from .voice_assistant_helpers import transcribe_audio_with_gemini, parse_command_with_gemini, process_date_filters

        # If audio is provided, transcribe it first
        if audio and mime_type:
            print(f'[VoiceAssistant] Transcribing audio (mime: {mime_type})')
            command = transcribe_audio_with_gemini(audio, mime_type)
            print(f'[VoiceAssistant] Transcribed text: {command}')
        from .voice_assistant_reports import (
            generate_alertas_report,
            generate_bitacora_report,
            generate_clientes_report,
            generate_facturas_report
        )

        # Parse command with Gemini
        parsed_command = parse_command_with_gemini(command)

        # Process filters
        filters = process_date_filters(parsed_command.get('filters', {}))

        # Generate report based on type
        report_type = parsed_command['reportType']
        format_type = parsed_command.get('format', 'PDF')

        if report_type == 'ALERTAS':
            result = generate_alertas_report(format_type, filters)
        elif report_type == 'BITACORA':
            result = generate_bitacora_report(format_type, filters)
        elif report_type == 'CLIENTES':
            result = generate_clientes_report(format_type, filters)
        elif report_type == 'FACTURAS':
            result = generate_facturas_report(format_type, filters)
        else:
            return Response({'message': 'Tipo de reporte no válido'},
                           status=status.HTTP_400_BAD_REQUEST)

        # Build response message
        response_message = f'Reporte de {report_type} generado exitosamente en formato {format_type}.'

        if not filters.get('fechaInicio') and not filters.get('fechaFin'):
            response_message += f' Se exportaron TODOS los registros. Total: {len(result["data"])} registros.'
        else:
            response_message += f' Intervalo: {filters["fechaInicio"]} a {filters["fechaFin"]}. Total: {len(result["data"])} registros.'

        return Response({
            'response': response_message,
            'action': 'generar_reporte',
            'reportType': report_type,
            'reportData': result['data'],
            'fileData': result['fileData'],
            'fileName': result['fileName'],
            'mimeType': result['mimeType'],
            'correctedCommand': f'Generar reporte de {report_type} en formato {format_type}',
            'transcript': command  # Include the transcribed/provided command
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({
            'message': 'Error al procesar el comando',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
