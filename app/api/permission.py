from rest_framework import permissions

ROLE_CHOICES = [
    ('citizen', 'Citizen'),
    ('worker', 'Worker'),
    ('department_admin', 'Department Admin'),
    ('superadmin', 'Super Admin'),
]

class IsSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'superadmin'

class IsDepartmentAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'department_admin'

class IsWorker(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'worker'

class IsCitizen(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'citizen'
