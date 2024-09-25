from django.urls import re_path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import *

app_name = "accounts"

router = DefaultRouter()
router.register("users", UserViewSet)
router.register("connections", ConnectionsViewSet)
router.register("connectionslog", ConnectionLogViewSet)

urlpatterns = [
    re_path("login/$", Login.as_view(), name="user_login"),
    re_path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
