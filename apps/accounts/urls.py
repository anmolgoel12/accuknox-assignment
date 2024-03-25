from django.urls import re_path
from rest_framework.routers import DefaultRouter

from .views import *

app_name = "accounts"

router = DefaultRouter()
router.register("users", UserViewSet)
router.register("connections", ConnectionsViewSet)

urlpatterns = [re_path("login/$", Login.as_view(), name="user_login")]
