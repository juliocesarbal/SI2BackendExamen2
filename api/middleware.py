from django.utils.deprecation import MiddlewareMixin
from .models import User
from .utils import verify_auth_token


class AuthMiddleware(MiddlewareMixin):
    """Middleware to authenticate users via access_token cookie"""

    def process_request(self, request):
        request.user = None
        token = request.COOKIES.get('access_token')

        if token:
            user_id = verify_auth_token(token)
            if user_id:
                try:
                    user = User.objects.get(id=user_id, is_active=True)
                    request.user = user
                except User.DoesNotExist:
                    pass

        return None
