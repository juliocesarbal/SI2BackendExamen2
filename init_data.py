"""
Script to initialize database with roles and permissions
Run this with: python manage.py shell < init_data.py
"""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from api.models import Role, Permission, RolePermission, User, UserRole

print("Creating permissions...")

# Define all permissions
permissions_data = [
    # User permissions
    {'key': 'user.read', 'description': 'View users'},
    {'key': 'user.create', 'description': 'Create users'},
    {'key': 'user.update', 'description': 'Update users'},
    {'key': 'user.delete', 'description': 'Delete users'},

    # Role permissions
    {'key': 'role.read', 'description': 'View roles'},
    {'key': 'role.create', 'description': 'Create roles'},
    {'key': 'role.update', 'description': 'Update roles'},
    {'key': 'role.delete', 'description': 'Delete roles'},

    # Inventory permissions
    {'key': 'inv.read', 'description': 'View inventory'},
    {'key': 'inv.create', 'description': 'Create inventory items'},
    {'key': 'inv.update', 'description': 'Update inventory'},
    {'key': 'inv.delete', 'description': 'Delete inventory items'},

    # Product permissions
    {'key': 'product.read', 'description': 'View products'},
    {'key': 'product.create', 'description': 'Create products'},
    {'key': 'product.update', 'description': 'Update products'},
    {'key': 'product.delete', 'description': 'Delete products'},

    # Order permissions
    {'key': 'order.read', 'description': 'View orders'},
    {'key': 'order.create', 'description': 'Create orders'},
    {'key': 'order.update', 'description': 'Update orders'},
    {'key': 'order.delete', 'description': 'Delete orders'},

    # Alert permissions
    {'key': 'alert.read', 'description': 'View alerts'},
    {'key': 'alert.create', 'description': 'Create alerts'},
    {'key': 'alert.update', 'description': 'Update alerts'},
    {'key': 'alert.delete', 'description': 'Delete alerts'},

    # Report permissions
    {'key': 'report.read', 'description': 'View reports'},
    {'key': 'report.create', 'description': 'Create reports'},

    # Bitacora permissions
    {'key': 'bitacora.read', 'description': 'View audit logs'},
]

for perm_data in permissions_data:
    permission, created = Permission.objects.get_or_create(
        key=perm_data['key'],
        defaults={'description': perm_data['description']}
    )
    if created:
        print(f"  Created permission: {permission.key}")
    else:
        print(f"  Permission already exists: {permission.key}")

print("\nCreating roles...")

# Create roles
admin_role, created = Role.objects.get_or_create(
    name='ADMIN',
    defaults={'description': 'Administrator with full access'}
)
if created:
    print("  Created role: ADMIN")
else:
    print("  Role already exists: ADMIN")

vendedor_role, created = Role.objects.get_or_create(
    name='VENDEDOR',
    defaults={'description': 'Sales person with limited access'}
)
if created:
    print("  Created role: VENDEDOR")
else:
    print("  Role already exists: VENDEDOR")

cliente_role, created = Role.objects.get_or_create(
    name='CLIENTE',
    defaults={'description': 'Customer with basic access'}
)
if created:
    print("  Created role: CLIENTE")
else:
    print("  Role already exists: CLIENTE")

print("\nAssigning permissions to roles...")

# Assign all permissions to ADMIN
admin_permissions = Permission.objects.all()
for perm in admin_permissions:
    RolePermission.objects.get_or_create(role=admin_role, permission=perm)
print(f"  Assigned {admin_permissions.count()} permissions to ADMIN")

# Assign specific permissions to VENDEDOR
vendedor_permission_keys = [
    'user.read', 'product.read', 'product.create', 'product.update',
    'inv.read', 'inv.create', 'inv.update', 'order.read', 'order.create',
    'order.update', 'alert.read', 'report.read'
]
for key in vendedor_permission_keys:
    try:
        perm = Permission.objects.get(key=key)
        RolePermission.objects.get_or_create(role=vendedor_role, permission=perm)
    except Permission.DoesNotExist:
        print(f"  Warning: Permission {key} not found")
print(f"  Assigned {len(vendedor_permission_keys)} permissions to VENDEDOR")

# Assign basic permissions to CLIENTE
cliente_permission_keys = ['product.read', 'order.read', 'order.create']
for key in cliente_permission_keys:
    try:
        perm = Permission.objects.get(key=key)
        RolePermission.objects.get_or_create(role=cliente_role, permission=perm)
    except Permission.DoesNotExist:
        print(f"  Warning: Permission {key} not found")
print(f"  Assigned {len(cliente_permission_keys)} permissions to CLIENTE")

print("\nCreating admin user...")

# Create an admin user
admin_user, created = User.objects.get_or_create(
    email='admin@example.com',
    defaults={
        'first_name': 'Admin',
        'last_name': 'User',
        'is_staff': True,
        'is_superuser': True,
    }
)

if created:
    admin_user.set_password('admin123')
    admin_user.save()
    UserRole.objects.get_or_create(user=admin_user, role=admin_role)
    print("  Created admin user: admin@example.com / admin123")
else:
    print("  Admin user already exists: admin@example.com")

print("\nInitialization complete!")
print("\nDefault admin credentials:")
print("  Email: admin@example.com")
print("  Password: admin123")
