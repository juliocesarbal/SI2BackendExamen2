"""
Script to generate synthetic sales data for ML model training
This creates realistic order data distributed over the past 6 months
"""
import os
import django
import random
from datetime import datetime, timedelta
from decimal import Decimal

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from api.models import User, Producto, Categoria, Orden, OrdenItem


def generate_synthetic_sales(num_orders=150):
    """
    Generate synthetic sales data

    Args:
        num_orders: Number of orders to generate (default: 150)
    """
    print(f"Starting generation of {num_orders} synthetic orders...")

    # Get all products and categories
    productos = list(Producto.objects.all())
    if len(productos) < 5:
        print("ERROR: Not enough products in database. Please add products first.")
        return

    categorias = list(Categoria.objects.all())
    if len(categorias) == 0:
        print("ERROR: No categories in database. Please add categories first.")
        return

    # Get all users (preferably clients)
    users = list(User.objects.all())
    if len(users) == 0:
        print("ERROR: No users in database. Please add users first.")
        return

    print(f"Found {len(productos)} products, {len(categorias)} categories, and {len(users)} users")

    # Generate orders distributed over the past 6 months
    end_date = datetime.now()
    start_date = end_date - timedelta(days=180)  # 6 months ago

    orders_created = 0
    orders_failed = 0

    for i in range(num_orders):
        try:
            # Random date within the range
            days_ago = random.randint(0, 180)
            order_date = end_date - timedelta(days=days_ago)

            # Random user
            user = random.choice(users)

            # Create order (created_at will be auto-set to now)
            orden = Orden.objects.create(
                user=user,
                total=Decimal('0.00'),  # Will be updated
                estado='COMPLETADO',  # All synthetic orders are completed
            )

            # Update dates manually (bypass auto_now_add)
            Orden.objects.filter(pk=orden.pk).update(
                created_at=order_date,
                updated_at=order_date
            )

            # Add random number of items (1-5)
            num_items = random.randint(1, 5)
            order_total = Decimal('0.00')

            for _ in range(num_items):
                producto = random.choice(productos)

                # Random quantity (1-10)
                cantidad = random.randint(1, 10)

                # Use product price with some variation (±10%)
                precio_base = Decimal(str(producto.precio))
                variacion = Decimal(str(random.uniform(0.9, 1.1)))
                precio_unitario = precio_base * variacion

                subtotal = precio_unitario * cantidad

                OrdenItem.objects.create(
                    orden=orden,
                    producto=producto,
                    cantidad=cantidad,
                    precio_unitario=precio_unitario,
                    subtotal=subtotal
                )

                order_total += subtotal

            # Update order total
            orden.total = order_total
            orden.save()

            orders_created += 1

            if (i + 1) % 10 == 0:
                print(f"Progress: {i + 1}/{num_orders} orders created...")

        except Exception as e:
            orders_failed += 1
            print(f"Error creating order {i + 1}: {e}")
            continue

    print("\n" + "=" * 50)
    print(f"✅ Synthetic data generation completed!")
    print(f"   Orders created: {orders_created}")
    print(f"   Orders failed: {orders_failed}")
    print(f"   Date range: {start_date.date()} to {end_date.date()}")
    print("=" * 50)

    # Show summary statistics
    show_statistics()


def show_statistics():
    """Show sales statistics after generation"""
    from django.db.models import Sum, Count, Avg

    total_orders = Orden.objects.filter(estado='COMPLETADO').count()
    total_revenue = Orden.objects.filter(estado='COMPLETADO').aggregate(Sum('total'))['total__sum'] or 0
    avg_order_value = Orden.objects.filter(estado='COMPLETADO').aggregate(Avg('total'))['total__avg'] or 0

    print("\n📊 Sales Statistics:")
    print(f"   Total Completed Orders: {total_orders}")
    print(f"   Total Revenue: ${total_revenue:.2f}")
    print(f"   Average Order Value: ${avg_order_value:.2f}")

    # Sales by category
    from api.models import OrdenItem
    items = OrdenItem.objects.filter(orden__estado='COMPLETADO')

    print("\n📦 Sales by Category:")
    sales_by_cat = items.values('producto__categoria__nombre').annotate(
        total=Sum('subtotal'),
        quantity=Sum('cantidad')
    ).order_by('-total')[:5]

    for i, cat in enumerate(sales_by_cat, 1):
        cat_name = cat['producto__categoria__nombre'] or 'Sin categoría'
        print(f"   {i}. {cat_name}: ${cat['total']:.2f} ({cat['quantity']} units)")

    print("\n🔥 Top Products:")
    top_products = items.values('producto__nombre').annotate(
        total=Sum('subtotal'),
        quantity=Sum('cantidad')
    ).order_by('-total')[:5]

    for i, prod in enumerate(top_products, 1):
        print(f"   {i}. {prod['producto__nombre']}: ${prod['total']:.2f} ({prod['quantity']} units)")


if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("   SYNTHETIC SALES DATA GENERATOR")
    print("=" * 50)

    # Ask user for number of orders
    try:
        num = input("\nHow many orders to generate? (default: 150): ").strip()
        num_orders = int(num) if num else 150
    except ValueError:
        print("Invalid input. Using default: 150")
        num_orders = 150

    confirm = input(f"\nThis will create {num_orders} synthetic orders. Continue? (y/n): ").strip().lower()

    if confirm == 'y':
        generate_synthetic_sales(num_orders)
        print("\n✨ You can now train the ML model using the Django admin or API endpoint!")
        print("   Endpoint: POST /api/analytics/model/train")
    else:
        print("Operation cancelled.")
