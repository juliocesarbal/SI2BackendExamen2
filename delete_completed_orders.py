"""
Script to delete all COMPLETADO orders (synthetic data cleanup)
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from api.models import Orden, OrdenItem

def delete_completed_orders():
    print("\n" + "="*60)
    print("   ELIMINANDO ÓRDENES COMPLETADAS")
    print("="*60)

    # Count orders before deletion
    completed_orders = Orden.objects.filter(estado='COMPLETADO')
    count = completed_orders.count()

    if count == 0:
        print("\nNo hay órdenes COMPLETADO para eliminar.")
        return

    print(f"\nSe encontraron {count} órdenes con estado COMPLETADO")

    confirm = input(f"\n¿Estás seguro de eliminar estas {count} órdenes? (s/n): ").strip().lower()

    if confirm != 's':
        print("Operación cancelada.")
        return

    # Delete order items first (foreign key constraint)
    items_deleted = OrdenItem.objects.filter(orden__estado='COMPLETADO').delete()
    print(f"\n✓ Items eliminados: {items_deleted[0]}")

    # Delete orders
    orders_deleted = completed_orders.delete()
    print(f"✓ Órdenes eliminadas: {orders_deleted[0]}")

    print("\n" + "="*60)
    print("✅ Limpieza completada exitosamente")
    print("="*60)

if __name__ == '__main__':
    delete_completed_orders()
