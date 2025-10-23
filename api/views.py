from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Q
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
    ClienteSerializer, CarritoItemSerializer, OrdenSerializer,
    LoteSerializer, AlertSerializer, BitacoraSerializer,
    PagoSerializer
)
from .utils import create_auth_token, get_client_ip, get_user_permissions
from django.conf import settings
import stripe

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
    """List clients with pagination"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    queryset = Cliente.objects.all()

    # Search
    q = request.GET.get('q', '')
    if q:
        queryset = queryset.filter(
            Q(nombre__icontains=q) |
            Q(apellido__icontains=q) |
            Q(email__icontains=q) |
            Q(nit__icontains=q)
        )

    # Filter by status
    status_filter = request.GET.get('status')
    if status_filter:
        queryset = queryset.filter(activo=(status_filter.lower() == 'active'))

    # Pagination
    page = int(request.GET.get('page', 1))
    size = int(request.GET.get('size', 10))
    total = queryset.count()

    start = (page - 1) * size
    end = start + size
    clientes = queryset[start:end]

    serializer = ClienteSerializer(clientes, many=True)

    return Response({
        'data': serializer.data,
        'total': total,
        'page': page,
        'size': size
    })


@api_view(['GET'])
def clientes_by_date_range(request):
    """Get clients by date range"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    fecha_inicial = request.GET.get('fechaInicial')
    fecha_final = request.GET.get('fechaFinal')

    queryset = Cliente.objects.all()

    if fecha_inicial:
        queryset = queryset.filter(created_at__gte=fecha_inicial)
    if fecha_final:
        queryset = queryset.filter(created_at__lte=fecha_final)

    serializer = ClienteSerializer(queryset, many=True)
    return Response(serializer.data)


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

    # Check if item already exists in cart
    cart_item, created = CarritoItem.objects.get_or_create(
        user=request.user,
        producto=producto,
        defaults={'cantidad': cantidad}
    )

    if not created:
        cart_item.cantidad += cantidad
        cart_item.save()

    serializer = CarritoItemSerializer(cart_item)
    return Response(serializer.data)


@api_view(['PATCH'])
def update_cart_item(request, item_id):
    """Update cart item quantity"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        item = CarritoItem.objects.get(id=item_id, user=request.user)
        cantidad = request.data.get('cantidad')

        if cantidad is not None:
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


@api_view(['POST'])
def checkout(request):
    """Create order from cart"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    # Get cart items
    cart_items = CarritoItem.objects.filter(user=request.user).select_related('producto')

    if not cart_items.exists():
        return Response({'message': 'Cart is empty'}, status=status.HTTP_400_BAD_REQUEST)

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

    # Create order items
    for item in cart_items:
        OrdenItem.objects.create(
            orden=orden,
            producto=item.producto,
            cantidad=item.cantidad,
            precio_unitario=item.producto.precio,
            subtotal=item.producto.precio * item.cantidad
        )

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

    data = request.data.copy()
    data['producto_id'] = producto_id

    serializer = LoteSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PATCH'])
def update_lote(request, lote_id):
    """Update batch"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        lote = Lote.objects.get(id=lote_id)
        serializer = LoteSerializer(lote, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
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
        lote.delete()
        return Response({'message': 'Lote deleted successfully'})
    except Lote.DoesNotExist:
        return Response({'message': 'Lote not found'}, status=status.HTTP_404_NOT_FOUND)


# ============== ALERTS ==============

@api_view(['GET'])
def list_alerts(request):
    """Get all alerts"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    alerts = Alert.objects.all().select_related('producto').order_by('-created_at')
    serializer = AlertSerializer(alerts, many=True)
    return Response(serializer.data)


@api_view(['PATCH'])
def mark_alert_read(request, alert_id):
    """Mark alert as read"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        alert = Alert.objects.get(id=alert_id)
        alert.leida = True
        alert.save()
        serializer = AlertSerializer(alert)
        return Response(serializer.data)
    except Alert.DoesNotExist:
        return Response({'message': 'Alert not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['PATCH'])
def mark_all_alerts_read(request):
    """Mark all alerts as read"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    Alert.objects.filter(leida=False).update(leida=True)
    return Response({'message': 'All alerts marked as read'})


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
    """Get audit logs with filters"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    queryset = Bitacora.objects.all().select_related('user')

    # Filters
    user_id = request.GET.get('userId')
    if user_id:
        queryset = queryset.filter(user_id=user_id)

    estado = request.GET.get('estado')
    if estado:
        queryset = queryset.filter(estado=estado)

    desde = request.GET.get('desde')
    if desde:
        queryset = queryset.filter(created_at__gte=desde)

    hasta = request.GET.get('hasta')
    if hasta:
        queryset = queryset.filter(created_at__lte=hasta)

    # Pagination
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('perPage', 10))

    total = queryset.count()
    start = (page - 1) * per_page
    end = start + per_page

    logs = queryset[start:end]
    serializer = BitacoraSerializer(logs, many=True)

    return Response({
        'data': serializer.data,
        'total': total,
        'page': page,
        'perPage': per_page
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

    try:
        orden = Orden.objects.get(id=orden_id, user=request.user)
    except Orden.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    # Create Stripe checkout session
    try:
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
            success_url='http://localhost:3000/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url='http://localhost:3000/cancel',
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

        return Response({'message': 'Payment confirmed'})
    except Pago.DoesNotExist:
        return Response({'message': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def list_pagos(request):
    """Get all payments/invoices"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    pagos = Pago.objects.filter(orden__user=request.user).select_related('orden')
    serializer = PagoSerializer(pagos, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def get_pago(request, pago_id):
    """Get specific payment/invoice"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        pago = Pago.objects.get(id=pago_id, orden__user=request.user)
        serializer = PagoSerializer(pago)
        return Response(serializer.data)
    except Pago.DoesNotExist:
        return Response({'message': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)


# ============== CHAT AI ==============

@api_view(['POST'])
def chat_ai(request):
    """Simple chat AI endpoint (placeholder)"""
    if not request.user:
        return Response({'message': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    message = request.data.get('message', '')

    # Placeholder response
    response_text = f"Recibí tu mensaje: '{message}'. Esta es una respuesta de prueba del chatbot."

    return Response({'response': response_text})
