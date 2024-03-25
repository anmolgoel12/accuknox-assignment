from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("The Email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, username=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, password, **extra_fields)


"""
Model for friends request 
    1- invite - Null
    2- accept - True
    3- reject - False
"""


class Connections(models.Model):
    from_user = models.ForeignKey(
        "accounts.User", related_name="from_user", on_delete=models.CASCADE
    )
    to_user = models.ForeignKey(
        "accounts.User", related_name="to_user", on_delete=models.CASCADE
    )
    state = models.BooleanField(default=None, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    u_timestamp = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Connections"


class User(AbstractUser):
    email = models.EmailField(unique=True, max_length=255, verbose_name="Email Address")
    name = models.CharField(max_length=500)
    connections = models.ManyToManyField(
        "accounts.User",
        blank=True,
        related_name="user_connections",
        through=Connections,
    )
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = UserManager()

    class Meta:
        verbose_name_plural = "User"
