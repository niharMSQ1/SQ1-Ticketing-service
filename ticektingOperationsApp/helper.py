# helper.py

from .models import UserApiMap

def get_user_permission_list(user):
    if user.is_superuser:
        return {}
    try:
        return UserApiMap.objects.get(user=user).apiList
    except UserApiMap.DoesNotExist:
        return {}
