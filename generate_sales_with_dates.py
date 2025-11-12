"""
Script to generate synthetic sales data with correct distributed dates
Uses raw SQL to bypass Django's auto_now_add and auto_now
"""
import os
import django
import random
from datetime import datetime, timedelta
from decimal import Decimal

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from api.models import User, Producto, Categoria, Orden, OrdenItem
from django.db import connection
from django.utils import timezone


def generate_synthetic_sales_with_dates(num_orders=150):
    """
    Generate synthetic sales data with distributed dates using raw SQL
    """
    print(f"\n{'='*60}")
    print(f"   GENERANDO {num_orders} ÓRDENES CON FECHAS DISTRIBUIDAS")
    print(f"{'='*60}\n")

    # Get all products EXCEPT those from "celulares" category
    productos = list(Producto.objects.exclude(categoria__nombre__iexact='celulares'))
    if len(productos) < 5:
        print("ERROR: No hay suficientes productos (excluyendo celulares). Agrega más productos primero.")
        return

    users = list(User.objects.all())
    if len(users) == 0:
        print("ERROR: No hay usuarios. Agrega usuarios primero.")
        return

    categorias = list(Categoria.objects.all())
    print(f"Encontrados: {len(productos)} productos, {len(categorias)} categorías, {len(users)} usuarios\n")

    # Generate orders distributed over the past 6 months
    end_date = datetime.now()
    start_date = end_date - timedelta(days=180)

    orders_created = 0
    orders_failed = 0

    with connection.cursor() as cursor:
        for i in range(num_orders):
            try:
                # Random date within the range
                days_ago = random.randint(0, 180)
                order_date = end_date - timedelta(days=days_ago)

                # Convert to timezone-aware datetime
                order_datetime = timezone.make_aware(order_date.replace(
                    hour=random.randint(8, 20),
                    minute=random.randint(0, 59),
                    second=random.randint(0, 59)
                ))

                # Random user
                user = random.choice(users)

                # Calculate order total first
                num_items = random.randint(1, 5)
                order_total = Decimal('0.00')

                items_data = []
                for _ in range(num_items):
                    producto = random.choice(productos)
                    cantidad = random.randint(1, 10)
                    precio_base = Decimal(str(producto.precio))
                    variacion = Decimal(str(random.uniform(0.9, 1.1)))
                    precio_unitario = precio_base * variacion
                    subtotal = precio_unitario * cantidad
                    order_total += subtotal

                    items_data.append({
                        'producto': producto,
                        'cantidad': cantidad,
                        'precio_unitario': precio_unitario,
                        'subtotal': subtotal
                    })

                # Insert order using raw SQL to set custom dates
                cursor.execute("""
                    INSERT INTO "orden" (user_id, total, estado, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id;
                """, [user.id, float(order_total), 'COMPLETADO', order_datetime, order_datetime])

                orden_id = cursor.fetchone()[0]

                # Insert order items
                for item_data in items_data:
                    cursor.execute("""
                        INSERT INTO "orden_item" (orden_id, producto_id, cantidad, precio_unitario, subtotal)
                        VALUES (%s, %s, %s, %s, %s);
                    """, [
                        orden_id,
                        item_data['producto'].id,
                        item_data['cantidad'],
                        float(item_data['precio_unitario']),
                        float(item_data['subtotal'])
                    ])

                orders_created += 1

                if (i + 1) % 10 == 0:
                    print(f"Progreso: {i + 1}/{num_orders} órdenes creadas...")

            except Exception as e:
                orders_failed += 1
                print(f"Error creando orden {i + 1}: {e}")
                continue

    print(f"\n{'='*60}")
    print(f"✅ Generación completada!")
    print(f"   Órdenes creadas: {orders_created}")
    print(f"   Órdenes fallidas: {orders_failed}")
    print(f"   Rango de fechas: {start_date.date()} a {end_date.date()}")
    print(f"{'='*60}")

    # Show summary statistics
    show_statistics()


def show_statistics():
    """Show sales statistics after generation"""
    from django.db.models import Sum, Count, Avg

    total_orders = Orden.objects.filter(estado='COMPLETADO').count()
    total_revenue = Orden.objects.filter(estado='COMPLETADO').aggregate(Sum('total'))['total__sum'] or 0
    avg_order_value = Orden.objects.filter(estado='COMPLETADO').aggregate(Avg('total'))['total__avg'] or 0

    print(f"\n📊 Estadísticas de Ventas:")
    print(f"   Total de Órdenes Completadas: {total_orders}")
    print(f"   Ingresos Totales: ${total_revenue:.2f}")
    print(f"   Valor Promedio por Orden: ${avg_order_value:.2f}")

    # Check date distribution
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT DATE(created_at) as fecha, COUNT(*) as num_ordenes
            FROM "orden"
            WHERE estado = 'COMPLETADO'
            GROUP BY DATE(created_at)
            ORDER BY fecha
            LIMIT 10;
        """)

        print(f"\n📅 Distribución de Fechas (primeras 10):")
        rows = cursor.fetchall()
        if rows:
            for fecha, num in rows:
                print(f"   {fecha}: {num} órdenes")
        else:
            print("   No hay datos disponibles")

    # Sales by category
    from api.models import OrdenItem
    items = OrdenItem.objects.filter(orden__estado='COMPLETADO')

    print(f"\n📦 Ventas por Categoría:")
    sales_by_cat = items.values('producto__categoria__nombre').annotate(
        total=Sum('subtotal'),
        quantity=Sum('cantidad')
    ).order_by('-total')[:5]

    for i, cat in enumerate(sales_by_cat, 1):
        cat_name = cat['producto__categoria__nombre'] or 'Sin categoría'
        print(f"   {i}. {cat_name}: ${cat['total']:.2f} ({cat['quantity']} unidades)")


if __name__ == '__main__':
    print(f"\n{'='*60}")
    print("   GENERADOR DE DATOS SINTÉTICOS CON FECHAS")
    print(f"{'='*60}")

    # Ask user for number of orders
    try:
        num = input("\n¿Cuántas órdenes generar? (default: 150): ").strip()
        num_orders = int(num) if num else 150
    except ValueError:
        print("Entrada inválida. Usando default: 150")
        num_orders = 150

    confirm = input(f"\nEsto creará {num_orders} órdenes sintéticas. ¿Continuar? (s/n): ").strip().lower()

    if confirm == 's':
        generate_synthetic_sales_with_dates(num_orders)
        print("\n✨ ¡Listo! Ahora puedes entrenar el modelo ML.")
        print("   Endpoint: POST /api/analytics/model/train")
    else:
        print("Operación cancelada.")
