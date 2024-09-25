from rest_framework.permissions import BasePermission


class RBACPermission(BasePermission):
    """
    Custom DRF permission to test if Read (only GET), Wite(GET, PATCH,PUT), Admin(No restriction)
    """

    def has_permission(self, request, view):
        method = request.method.lower()
        user = request.user
        group = user.groups.last()
        if not group:
            return True
        pk = group.id
        if method in ["post", "put", "patch"] and pk in [1, 2]:
            return True
        if method == "delete" and pk == 1:
            return True
        if method == "get":
            return True
        return False
