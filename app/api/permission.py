from rest_framework import permissions

ROLE_CHOICES = [
    ('citizen', 'Citizen'),
    ('worker', 'Worker'),
    ('department_admin', 'Department Admin'),
    ('department_head', 'Department Head'),
    ('superadmin', 'Super Admin'),
]

class IsSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        # Ensure the user is authenticated and has the correct role
        return request.user.is_authenticated and request.user.role == 'superadmin'

class IsDepartmentAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        # Ensure the user is authenticated and has the correct role
        return request.user.is_authenticated and request.user.role == 'department_admin'

class IsWorker(permissions.BasePermission):
    def has_permission(self, request, view):
        # Ensure the user is authenticated and has the correct role
        return request.user.is_authenticated and request.user.role == 'worker'

class IsCitizen(permissions.BasePermission):
    def has_permission(self, request, view):
        # Ensure the user is authenticated, has the correct role, and has a verified email
        return request.user.is_authenticated and request.user.role == 'citizen' and request.user.is_email_verified
