from django.conf import settings
from django.conf.urls import include, static
from django.urls import include, path, re_path
from django.views.generic import TemplateView
from rest_framework.routers import DefaultRouter

from apps.accounts.urls import router as accounts_router

MEDIA_ROOT = settings.MEDIA_ROOT
MEDIA_URL = settings.MEDIA_URL
STATIC_URL = settings.STATIC_URL

router = DefaultRouter()
router.registry.extend(accounts_router.registry)


urlpatterns = [
    path(
        "direct-html/",
        TemplateView.as_view(template_name="pay.html"),
        name="direct_html",
    ),
    re_path(r"^api/v1/", include(router.urls)),
    re_path(r"^api/v1/", include("apps.accounts.urls", namespace="accounts")),
]

urlpatterns += static.static(MEDIA_URL, document_root=MEDIA_ROOT)
