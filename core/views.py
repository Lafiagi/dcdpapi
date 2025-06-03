from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from core.models import PcapFile, NetworkConnection, ThreatDetection, AnalysisResult
from core.serializers import (
    PcapFileSerializer,
    PcapFileDetailSerializer,
    NetworkConnectionSerializer,
    ThreatDetectionSerializer,
    AnalysisResultSerializer,
)
from core.tasks import analyze_pcap_file
from core.utils import validate_pcap_file


class PcapFileViewSet(viewsets.ModelViewSet):
    serializer_class = PcapFileSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["status"]

    def get_queryset(self):
        return PcapFile.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.action == "retrieve":
            return PcapFileDetailSerializer
        return PcapFileSerializer

    def perform_create(self, serializer):
        uploaded_file = self.request.FILES["file"]

        # Validate file type
        if not validate_pcap_file(uploaded_file):
            return Response(
                {"error": "Invalid file type. Only PCAP files are allowed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Save the file
        pcap_file = serializer.save(
            user=self.request.user,
            filename=uploaded_file.name,
            file_size=uploaded_file.size,
        )

        return Response(
            PcapFileSerializer(pcap_file).data, status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=["post"])
    def start_analysis(self, request, pk=None):
        pcap_file = self.get_object()

        if pcap_file.status in ["analyzing", "completed"]:
            return Response(
                {"error": f"File is already {pcap_file.status}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Queue the analysis task
        pcap_file.status = "queued"
        pcap_file.save()

        # Start Celery task
        analyze_pcap_file.delay(str(pcap_file.id))

        return Response({"message": "Analysis started", "status": pcap_file.status})

    @action(detail=True, methods=["get"])
    def analysis_status(self, request, pk=None):
        pcap_file = self.get_object()
        return Response(
            {
                "status": pcap_file.status,
                "uploaded_at": pcap_file.uploaded_at,
                "analysis_started_at": pcap_file.analysis_started_at,
                "analysis_completed_at": pcap_file.analysis_completed_at,
                "error_message": pcap_file.error_message,
            }
        )

    @action(detail=True, methods=["get"])
    def download_report(self, request, pk=None):
        pcap_file = self.get_object()

        if pcap_file.status != "completed":
            return Response(
                {"error": "Analysis not completed yet"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Generate and return report
        report_data = self._generate_report(pcap_file)
        return Response(report_data)

    def _generate_report(self, pcap_file):
        analysis_result = getattr(pcap_file, "analysis_result", None)
        threats = pcap_file.threats.all()

        return {
            "file_info": {
                "filename": pcap_file.filename,
                "file_size": pcap_file.file_size,
                "analyzed_at": pcap_file.analysis_completed_at,
            },
            "summary": {
                "total_packets": (
                    analysis_result.total_packets if analysis_result else 0
                ),
                "total_bytes": analysis_result.total_bytes if analysis_result else 0,
                "duration": analysis_result.duration if analysis_result else 0,
                "threats_found": threats.count(),
            },
            "protocol_distribution": (
                analysis_result.protocol_distribution if analysis_result else {}
            ),
            "threats": ThreatDetectionSerializer(threats, many=True).data,
            "top_sources": analysis_result.top_sources if analysis_result else [],
            "timeline": analysis_result.timeline_data if analysis_result else [],
        }

    @action(detail=False, methods=["get"])
    def dashboard_analytics(self, request, pk=None):
        total_pcap = PcapFile.objects.count()
        total_analyzed = PcapFile.objects.filter(status="completed").count()
        total_threats = ThreatDetection.objects.count()
        total_network_connections = NetworkConnection.objects.count()
        return Response(
            {
                "total_pcap": total_pcap,
                "total_analyzed": total_analyzed,
                "total_threats": total_threats,
                "total_network_connections": total_network_connections,
            },
            status=status.HTTP_200_OK,
        )


class NetworkConnectionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = NetworkConnectionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["protocol", "source_ip", "destination_ip"]

    def get_queryset(self):
        return NetworkConnection.objects.filter(pcap_file__user=self.request.user)


class ThreatDetectionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ThreatDetectionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["threat_type", "severity", "source_ip"]

    def get_queryset(self):
        return ThreatDetection.objects.filter(pcap_file__user=self.request.user)


class AnalysisResultView(viewsets.ReadOnlyModelViewSet):
    serializer_class = AnalysisResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]

    def get_queryset(self):
        return AnalysisResult.objects.filter(pcap_file__user=self.request.user)
