from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.routers import DefaultRouter
from core.views import (
    PcapFileViewSet,
    NetworkConnectionViewSet,
    ThreatDetectionViewSet,
    AnalysisResultView,
)

router = DefaultRouter()
router.register(r"pcap-files", PcapFileViewSet, basename="pcapfile")
router.register(r"connections", NetworkConnectionViewSet, basename="connection")
router.register(r"threats", ThreatDetectionViewSet, basename="threat")
router.register(r"analysis", AnalysisResultView, basename="analysis")

# urlpatterns = [
#     path('api/auth/login/', obtain_auth_token, name='api_token_auth'),
# ]
urlpatterns = [
    path("api/auth/login/", obtain_auth_token, name="api_token_auth"),
    path("api/", include(router.urls)),
]
