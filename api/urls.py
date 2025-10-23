from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('auth/login', views.login, name='login'),
    path('auth/logout', views.logout, name='logout'),
    path('me', views.me, name='me'),

    # Public endpoints
    path('public/register', views.register, name='register'),
    path('public/productos', views.public_productos, name='public_productos'),
    path('public/categorias', views.public_categorias, name='public_categorias'),

    # Users management
    path('users', views.list_users, name='list_users'),
    path('users/internal', views.create_internal_user, name='create_internal_user'),
    path('users/<int:user_id>', views.user_detail, name='user_detail'),
    path('users/clientes', views.list_clientes, name='list_clientes'),
    path('users/clientes/by-date-range', views.clientes_by_date_range, name='clientes_by_date_range'),

    # Roles & Permissions
    path('roles', views.list_roles, name='list_roles'),
    path('roles/create', views.create_role, name='create_role'),
    path('roles/<int:role_id>', views.get_role, name='get_role'),
    path('roles/<int:role_id>/update', views.update_role, name='update_role'),
    path('roles/<int:role_id>/delete', views.delete_role, name='delete_role'),
    path('roles/<int:role_id>/permissions', views.get_role_permissions, name='get_role_permissions'),
    path('roles/<int:role_id>/permissions/update', views.update_role_permissions, name='update_role_permissions'),
    path('permissions', views.list_permissions, name='list_permissions'),

    # Shopping Cart
    path('carrito', views.get_cart, name='get_cart'),
    path('carrito/add', views.add_to_cart, name='add_to_cart'),
    path('carrito/<int:item_id>', views.update_cart_item, name='update_cart_item'),
    path('carrito/<int:item_id>/delete', views.remove_cart_item, name='remove_cart_item'),
    path('carrito/clear', views.clear_cart, name='clear_cart'),
    path('carrito/checkout', views.checkout, name='checkout'),

    # Categories, Brands & Units
    path('categorias', views.categorias, name='categorias'),
    path('categorias/<int:categoria_id>', views.categoria_detail, name='categoria_detail'),
    path('marcas', views.marcas, name='marcas'),
    path('marcas/<int:marca_id>', views.marca_detail, name='marca_detail'),
    path('unidades', views.unidades, name='unidades'),
    path('unidades/<int:unidad_id>', views.unidad_detail, name='unidad_detail'),

    # Products
    path('productos', views.productos, name='productos'),
    path('productos/<int:producto_id>', views.producto_detail, name='producto_detail'),

    # Products & Inventory (Lotes)
    path('productos/<int:producto_id>/lotes', views.get_producto_lotes, name='get_producto_lotes'),
    path('productos/<int:producto_id>/lotes/create', views.create_lote, name='create_lote'),
    path('lotes/<int:lote_id>', views.update_lote, name='update_lote'),
    path('lotes/<int:lote_id>/delete', views.delete_lote, name='delete_lote'),

    # Alerts
    path('alerts', views.list_alerts, name='list_alerts'),
    path('alerts/<int:alert_id>/read', views.mark_alert_read, name='mark_alert_read'),
    path('alerts/read-all', views.mark_all_alerts_read, name='mark_all_alerts_read'),

    # Audit Log
    path('bitacora', views.list_bitacora, name='list_bitacora'),
    path('bitacora/create', views.create_bitacora, name='create_bitacora'),

    # Payments
    path('pagos/crear', views.create_pago, name='create_pago'),
    path('pagos/confirmar', views.confirm_pago, name='confirm_pago'),
    path('pagos/facturas', views.list_pagos, name='list_pagos'),
    path('pagos/factura/<int:pago_id>', views.get_pago, name='get_pago'),

    # Chat AI
    path('chat-ai', views.chat_ai, name='chat_ai'),
]
