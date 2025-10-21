from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from django.utils.functional import SimpleLazyObject
from .models import User
from .utils import verify_auth_token


class AuthMiddleware(MiddlewareMixin):
    """Middleware to authenticate users via access_token cookie"""

    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        Process view runs AFTER all middleware process_request,
        giving us a chance to override Django's authentication
        """
        # Get token from cookies
        token = request.COOKIES.get('access_token')

        print(f"DEBUG AuthMiddleware.process_view: path={request.path}, has_token={bool(token)}")

        if token:
            try:
                user_id = verify_auth_token(token)
                if user_id:
                    try:
                        user = User.objects.get(id=user_id, is_active=True)
                        # CRITICAL: Delete the lazy object attribute and replace with real user
                        # This prevents re-evaluation
                        if hasattr(request, '_cached_user'):
                            delattr(request, '_cached_user')

                        # Replace completely, not just the _wrapped
                        object.__setattr__(request, 'user', user)

                        print(f"DEBUG AuthMiddleware.process_view: Set user to {user.email}")
                        print(f"DEBUG AuthMiddleware.process_view: user after = {type(request.user)}, id={request.user.id}")
                        return None  # Continue to view
                    except User.DoesNotExist:
                        print(f"DEBUG AuthMiddleware: User {user_id} not found")
            except Exception as e:
                import traceback
                print(f"Error verifying token: {e}")
                traceback.print_exc()

        # If we get here, no valid token - set to None
        if hasattr(request, '_cached_user'):
            delattr(request, '_cached_user')
        object.__setattr__(request, 'user', None)
        print(f"DEBUG AuthMiddleware.process_view: Set user to None")

        return None  # Continue to view
