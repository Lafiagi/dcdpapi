from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    # Admin panel
    path("admin/", admin.site.urls),
    # API Schema endpoint (required for Swagger/Redoc)
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    # API Documentation endpoints
    path(
        "apidocs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        "api/schema/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
    # Core app URLs
    path("", include("core.urls")),  # Prefix API routes with /api/
    # Optional: Root redirect or home page
    # path("", RedirectView.as_view(url="/api/docs/", permanent=False)),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
