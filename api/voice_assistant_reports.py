"""
Voice Assistant Report Generators
Generates different types of reports: Alertas, Bitácora, Clientes, Facturas
"""

from django.db.models import F
from .models import Producto, Bitacora, User, Role, UserRole, Orden
from .voice_assistant_helpers import generate_file


def generate_alertas_report(format_type, filters):
    """Generate alerts report"""
    # Get products with low stock
    productos = Producto.objects.filter(
        activo=True,
        stock_actual__lte=F('stock_minimo')
    ).select_related('marca', 'categoria').order_by('stock_actual')

    data = [{
        'id': p.id,
        'nombre': p.nombre,
        'marca': p.marca.nombre if p.marca else 'N/A',
        'categoria': p.categoria.nombre if p.categoria else 'N/A',
        'stockActual': p.stock_actual,
        'stockMinimo': p.stock_minimo,
        'diferencia': p.stock_actual - p.stock_minimo,
        'precio': str(p.precio)
    } for p in productos]

    columns = [
        {'header': 'ID', 'key': 'id'},
        {'header': 'Producto', 'key': 'nombre'},
        {'header': 'Marca', 'key': 'marca'},
        {'header': 'Categoría', 'key': 'categoria'},
        {'header': 'Stock Actual', 'key': 'stockActual'},
        {'header': 'Stock Mínimo', 'key': 'stockMinimo'},
        {'header': 'Diferencia', 'key': 'diferencia'},
        {'header': 'Precio', 'key': 'precio'},
    ]

    file_result = generate_file('Alertas_de_Inventario', format_type, data, columns)

    return {
        'data': data,
        **file_result
    }


def generate_bitacora_report(format_type, filters):
    """Generate audit log report"""
    queryset = Bitacora.objects.all().select_related('user')

    if filters.get('fechaInicio') and filters.get('fechaFin'):
        queryset = queryset.filter(
            created_at__gte=filters['fechaInicio'],
            created_at__lte=filters['fechaFin']
        )

    if filters.get('tipo'):
        queryset = queryset.filter(estado=filters['tipo'])

    registros = queryset.order_by('-created_at')

    data = [{
        'id': r.id,
        'estado': r.estado,
        'acciones': r.acciones,
        'usuario': f"{r.user.first_name} {r.user.last_name} ({r.user.email})" if r.user else 'N/A',
        'ip': r.ip or 'N/A',
        'fecha': r.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for r in registros]

    columns = [
        {'header': 'ID', 'key': 'id'},
        {'header': 'Estado', 'key': 'estado'},
        {'header': 'Acciones', 'key': 'acciones'},
        {'header': 'Usuario', 'key': 'usuario'},
        {'header': 'IP', 'key': 'ip'},
        {'header': 'Fecha', 'key': 'fecha'},
    ]

    file_result = generate_file('Bitácora_de_Seguridad', format_type, data, columns)

    return {
        'data': data,
        **file_result
    }


def generate_clientes_report(format_type, filters):
    """Generate clients report"""
    try:
        cliente_role = Role.objects.get(name='CLIENTE')
        user_ids = UserRole.objects.filter(role=cliente_role).values_list('user_id', flat=True)
        queryset = User.objects.filter(id__in=user_ids)
    except Role.DoesNotExist:
        queryset = User.objects.none()

    if filters.get('fechaInicio') and filters.get('fechaFin'):
        queryset = queryset.filter(
            created_at__gte=filters['fechaInicio'],
            created_at__lte=filters['fechaFin']
        )

    clientes = queryset.order_by('-created_at')

    data = [{
        'id': c.id,
        'nombre': f"{c.first_name} {c.last_name}",
        'email': c.email,
        'telefono': c.telefono or 'N/A',
        'fechaRegistro': c.created_at.strftime('%Y-%m-%d'),
        'totalOrdenes': Orden.objects.filter(user=c).count()
    } for c in clientes]

    columns = [
        {'header': 'ID', 'key': 'id'},
        {'header': 'Nombre', 'key': 'nombre'},
        {'header': 'Email', 'key': 'email'},
        {'header': 'Teléfono', 'key': 'telefono'},
        {'header': 'Fecha Registro', 'key': 'fechaRegistro'},
        {'header': 'Total Órdenes', 'key': 'totalOrdenes'},
    ]

    file_result = generate_file('Reporte_de_Clientes', format_type, data, columns)

    return {
        'data': data,
        **file_result
    }


def generate_facturas_report(format_type, filters):
    """Generate invoices/orders report"""
    queryset = Orden.objects.all().select_related('user').prefetch_related('items__producto')

    if filters.get('fechaInicio') and filters.get('fechaFin'):
        queryset = queryset.filter(
            created_at__gte=filters['fechaInicio'],
            created_at__lte=filters['fechaFin']
        )

    ordenes = queryset.order_by('-created_at')

    data = [{
        'id': o.id,
        'cliente': f"{o.user.first_name} {o.user.last_name}",
        'email': o.user.email,
        'fecha': o.created_at.strftime('%Y-%m-%d'),
        'estado': o.estado,
        'total': str(o.total),
        'productos': o.items.count(),
        'detalleProductos': ', '.join([f"{item.producto.nombre} ({item.cantidad})" for item in o.items.all()])
    } for o in ordenes]

    columns = [
        {'header': 'ID', 'key': 'id'},
        {'header': 'Cliente', 'key': 'cliente'},
        {'header': 'Email', 'key': 'email'},
        {'header': 'Fecha', 'key': 'fecha'},
        {'header': 'Estado', 'key': 'estado'},
        {'header': 'Total', 'key': 'total'},
        {'header': '# Productos', 'key': 'productos'},
        {'header': 'Detalle', 'key': 'detalleProductos'},
    ]

    file_result = generate_file('Reporte_de_Facturas', format_type, data, columns)

    return {
        'data': data,
        **file_result
    }
