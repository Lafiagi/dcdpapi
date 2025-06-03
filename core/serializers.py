from rest_framework import serializers
from core.models import PcapFile, NetworkConnection, ThreatDetection, AnalysisResult


class PcapFileSerializer(serializers.ModelSerializer):
    file_size_human = serializers.SerializerMethodField()

    class Meta:
        model = PcapFile
        fields = [
            "id",
            "filename",
            "file",
            "file_size",
            "file_size_human",
            "status",
            "uploaded_at",
            "analysis_started_at",
            "analysis_completed_at",
            "error_message",
        ]
        read_only_fields = [
            "id",
            "user",
            "uploaded_at",
            "analysis_started_at",
            "analysis_completed_at",
            "filename",
            "file_size"
        ]

    def get_file_size_human(self, obj):
        bytes_size = obj.file_size
        if bytes_size == 0:
            return "0 Bytes"

        size_names = ["Bytes", "KB", "MB", "GB", "TB"]
        i = 0
        while bytes_size >= 1024 and i < len(size_names) - 1:
            bytes_size /= 1024.0
            i += 1
        return f"{bytes_size:.2f} {size_names[i]}"


class NetworkConnectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkConnection
        fields = "__all__"


class ThreatDetectionSerializer(serializers.ModelSerializer):
    threat_type_display = serializers.CharField(
        source="get_threat_type_display", read_only=True
    )
    severity_display = serializers.CharField(
        source="get_severity_display", read_only=True
    )

    class Meta:
        model = ThreatDetection
        fields = "__all__"


class AnalysisResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalysisResult
        fields = "__all__"


class PcapFileDetailSerializer(serializers.ModelSerializer):
    # connections = NetworkConnectionSerializer(many=True, read_only=True)
    threats = ThreatDetectionSerializer(many=True, read_only=True)
    analysis_result = AnalysisResultSerializer(read_only=True)
    file_size_human = serializers.SerializerMethodField()

    class Meta:
        model = PcapFile
        fields = [
            "id",
            "filename",
            "file_size",
            "file_size_human",
            "status",
            "uploaded_at",
            "analysis_started_at",
            "analysis_completed_at",
            "error_message",
            # "connections",
            "threats",
            "analysis_result",
        ]

    def get_file_size_human(self, obj):
        bytes_size = obj.file_size
        if bytes_size == 0:
            return "0 Bytes"

        size_names = ["Bytes", "KB", "MB", "GB", "TB"]
        i = 0
        while bytes_size >= 1024 and i < len(size_names) - 1:
            bytes_size /= 1024.0
            i += 1
        return f"{bytes_size:.2f} {size_names[i]}"
