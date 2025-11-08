from rest_framework.views import exception_handler
from rest_framework.response import Response
from django.core.signing import TimestampSigner, BadSignature
from .models import User, UserRole
import secrets


def custom_exception_handler(exc, context):
    """Custom exception handler for REST framework"""
    response = exception_handler(exc, context)

    if response is not None:
        custom_response = {
            'message': response.data.get('detail', str(exc))
        }
        response.data = custom_response

    return response


def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


def create_auth_token(user_id):
    """Create a signed authentication token"""
    signer = TimestampSigner()
    token = f"{user_id}:{secrets.token_urlsafe(32)}"
    return signer.sign(token)


def verify_auth_token(token):
    """Verify and decode authentication token"""
    try:
        signer = TimestampSigner()
        unsigned = signer.unsign(token, max_age=60*60*24*7)  # 7 days
        user_id = int(unsigned.split(':')[0])
        return user_id
    except (BadSignature, ValueError):
        return None


def get_user_permissions(user):
    """Get all permissions for a user based on their roles"""
    permissions = set()
    user_roles = UserRole.objects.filter(user=user).select_related('role')

    for user_role in user_roles:
        role_permissions = user_role.role.role_permissions.select_related('permission')
        for rp in role_permissions:
            permissions.add(rp.permission.key)

    return list(permissions)


def has_permission(user, permission_key):
    """Check if user has a specific permission"""
    if user.is_superuser:
        return True

    permissions = get_user_permissions(user)
    return permission_key in permissions


def log_ok(request, acciones):
    """
    Log successful action to bitacora

    Args:
        request: Django request object
        acciones: Description of the action (str)
    """
    from .models import Bitacora

    if not request.user or not hasattr(request.user, 'id'):
        return

    try:
        Bitacora.objects.create(
            user=request.user,
            ip=get_client_ip(request),
            acciones=acciones,
            estado='EXITOSO'
        )
    except Exception as e:
        # Don't let logging errors break the app
        print(f"Error logging to bitacora: {e}")


def log_fail(request, acciones):
    """
    Log failed action to bitacora

    Args:
        request: Django request object
        acciones: Description of the action (str)
    """
    from .models import Bitacora

    if not request.user or not hasattr(request.user, 'id'):
        return

    try:
        Bitacora.objects.create(
            user=request.user,
            ip=get_client_ip(request),
            acciones=acciones,
            estado='FALLIDO'
        )
    except Exception as e:
        # Don't let logging errors break the app
        print(f"Error logging to bitacora: {e}")
