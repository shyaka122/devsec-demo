"""
Management command to initialize authorization groups and permissions.
Run this after initial deployment: python manage.py setup_authorization_groups
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission


class Command(BaseCommand):
    help = 'Initialize authorization groups (admin, staff, user)'

    def handle(self, *args, **options):
        # Define the groups and their descriptions
        groups_data = {
            'admin': 'Full system access and user management',
            'staff': 'Elevated permissions for instructors and moderators',
            'user': 'Standard authenticated user permissions',
        }

        for group_name, description in groups_data.items():
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Created group: {group_name}')
                )
                self.stdout.write(f'  Description: {description}')
            else:
                self.stdout.write(f'ℹ Group already exists: {group_name}')

        self.stdout.write(
            self.style.SUCCESS('\n✓ Authorization groups initialized successfully.')
        )
        self.stdout.write(
            self.style.WARNING(
                '\nNote: Assign users to groups in Django admin or via:\n'
                '  user.groups.add(Group.objects.get(name="group_name"))'
            )
        )
