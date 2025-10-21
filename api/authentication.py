from rest_framework.authentication import BaseAuthentication
from django.core.signing import TimestampSigner, BadSignature
from .models import User


def verify_auth_token(token):
    """Verify and decode authentication token"""
    try:
        signer = TimestampSigner()
        unsigned = signer.unsign(token, max_age=60*60*24*7)  # 7 days
        user_id = int(unsigned.split(':')[0])
        return user_id
    except (BadSignature, ValueError):
        return None


class CookieTokenAuthentication(BaseAuthentication):
    """
    Custom authentication class for Django Rest Framework
    that authenticates using the access_token cookie
    """

    def authenticate(self, request):
        """
        Returns a `User` if a valid token is found in cookies,
        otherwise returns None.
        """
        # Get token from cookies
        token = request.COOKIES.get('access_token')

        if not token:
            print("DEBUG CookieTokenAuthentication: No token found")
            return None

        try:
            user_id = verify_auth_token(token)
            if user_id:
                try:
                    user = User.objects.get(id=user_id, is_active=True)
                    print(f"DEBUG CookieTokenAuthentication: Authenticated user {user.email}")
                    # Return (user, None) - None is the auth token
                    return (user, None)
                except User.DoesNotExist:
                    print(f"DEBUG CookieTokenAuthentication: User {user_id} not found")
                    return None
        except Exception as e:
            import traceback
            print(f"DEBUG CookieTokenAuthentication: Error verifying token: {e}")
            traceback.print_exc()
            return None

        return None
