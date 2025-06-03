from django.db import models
from django.contrib.auth.models import User
import uuid


class PcapFile(models.Model):
    STATUS_CHOICES = [
        ("uploaded", "Uploaded"),
        ("queued", "Queued for Analysis"),
        ("analyzing", "Analyzing"),
        ("completed", "Analysis Complete"),
        ("failed", "Analysis Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to="pcap_files/")
    file_size = models.BigIntegerField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="uploaded")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    analysis_started_at = models.DateTimeField(null=True, blank=True)
    analysis_completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-uploaded_at"]


class NetworkConnection(models.Model):
    pcap_file = models.ForeignKey(
        PcapFile, on_delete=models.CASCADE, related_name="connections"
    )

    # Basic connection info
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    timestamp = models.DateTimeField()

    # Flow features (based on CIC-IDS2017 dataset features)
    flow_duration = models.BigIntegerField(default=0)  # microseconds
    total_fwd_packets = models.IntegerField(default=0)
    total_backward_packets = models.IntegerField(default=0)
    total_length_fwd_packets = models.BigIntegerField(default=0)
    total_length_bwd_packets = models.BigIntegerField(default=0)

    # Forward packet statistics
    fwd_packet_length_max = models.IntegerField(default=0)
    fwd_packet_length_min = models.IntegerField(default=0)
    fwd_packet_length_mean = models.FloatField(default=0.0)
    fwd_packet_length_std = models.FloatField(default=0.0)

    # Backward packet statistics
    bwd_packet_length_max = models.IntegerField(default=0)
    bwd_packet_length_min = models.IntegerField(default=0)
    bwd_packet_length_mean = models.FloatField(default=0.0)
    bwd_packet_length_std = models.FloatField(default=0.0)

    # Flow inter-arrival times
    flow_iat_mean = models.FloatField(default=0.0)
    flow_iat_std = models.FloatField(default=0.0)
    flow_iat_max = models.BigIntegerField(default=0)
    flow_iat_min = models.BigIntegerField(default=0)

    # Forward/Backward IAT
    fwd_iat_total = models.BigIntegerField(default=0)
    fwd_iat_mean = models.FloatField(default=0.0)
    fwd_iat_std = models.FloatField(default=0.0)
    fwd_iat_max = models.BigIntegerField(default=0)
    fwd_iat_min = models.BigIntegerField(default=0)

    bwd_iat_total = models.BigIntegerField(default=0)
    bwd_iat_mean = models.FloatField(default=0.0)
    bwd_iat_std = models.FloatField(default=0.0)
    bwd_iat_max = models.BigIntegerField(default=0)
    bwd_iat_min = models.BigIntegerField(default=0)

    # TCP flags
    fwd_psh_flags = models.IntegerField(default=0)
    bwd_psh_flags = models.IntegerField(default=0)
    fwd_urg_flags = models.IntegerField(default=0)
    bwd_urg_flags = models.IntegerField(default=0)
    fwd_header_length = models.IntegerField(default=0)
    bwd_header_length = models.IntegerField(default=0)

    # Packets per second
    fwd_packets_per_second = models.FloatField(default=0.0)
    bwd_packets_per_second = models.FloatField(default=0.0)

    # Packet length statistics
    min_packet_length = models.IntegerField(default=0)
    max_packet_length = models.IntegerField(default=0)
    packet_length_mean = models.FloatField(default=0.0)
    packet_length_std = models.FloatField(default=0.0)
    packet_length_variance = models.FloatField(default=0.0)

    # Flag counts
    fin_flag_count = models.IntegerField(default=0)
    syn_flag_count = models.IntegerField(default=0)
    rst_flag_count = models.IntegerField(default=0)
    psh_flag_count = models.IntegerField(default=0)
    ack_flag_count = models.IntegerField(default=0)
    urg_flag_count = models.IntegerField(default=0)
    cwe_flag_count = models.IntegerField(default=0)
    ece_flag_count = models.IntegerField(default=0)

    # Window sizes
    down_up_ratio = models.FloatField(default=0.0)
    average_packet_size = models.FloatField(default=0.0)
    avg_fwd_segment_size = models.FloatField(default=0.0)
    avg_bwd_segment_size = models.FloatField(default=0.0)

    # Subflow features
    fwd_byts_per_bulk_avg = models.FloatField(default=0.0)
    fwd_pkts_per_bulk_avg = models.FloatField(default=0.0)
    fwd_blk_rate_avg = models.FloatField(default=0.0)
    bwd_byts_per_bulk_avg = models.FloatField(default=0.0)
    bwd_pkts_per_bulk_avg = models.FloatField(default=0.0)
    bwd_blk_rate_avg = models.FloatField(default=0.0)

    # Active/Idle features
    subflow_fwd_packets = models.IntegerField(default=0)
    subflow_fwd_bytes = models.IntegerField(default=0)
    subflow_bwd_packets = models.IntegerField(default=0)
    subflow_bwd_bytes = models.IntegerField(default=0)

    init_win_bytes_forward = models.IntegerField(default=0)
    init_win_bytes_backward = models.IntegerField(default=0)
    act_data_pkt_fwd = models.IntegerField(default=0)
    min_seg_size_forward = models.IntegerField(default=0)

    active_mean = models.FloatField(default=0.0)
    active_std = models.FloatField(default=0.0)
    active_max = models.BigIntegerField(default=0)
    active_min = models.BigIntegerField(default=0)

    idle_mean = models.FloatField(default=0.0)
    idle_std = models.FloatField(default=0.0)
    idle_max = models.BigIntegerField(default=0)
    idle_min = models.BigIntegerField(default=0)

    # ML prediction fields
    is_malicious = models.BooleanField(default=False)
    attack_type = models.CharField(max_length=50, blank=True)
    confidence_score = models.FloatField(default=0.0)
    
    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["source_ip", "destination_ip"]),
            models.Index(fields=["timestamp"]),
            models.Index(fields=["is_malicious"]),
        ]


class MLModel(models.Model):
    """Store ML model metadata and performance metrics"""

    MODEL_TYPES = [
        ("binary", "Binary Classification (Benign/Malicious)"),
        ("multiclass", "Multi-class Classification (Attack Types)"),
        ("anomaly", "Anomaly Detection"),
    ]

    name = models.CharField(max_length=100)
    model_type = models.CharField(max_length=20, choices=MODEL_TYPES)
    algorithm = models.CharField(max_length=50)  # RandomForest, XGBoost, etc.
    version = models.CharField(max_length=20)
    file_path = models.CharField(max_length=500)  # Path to saved model

    # Training metrics
    accuracy = models.FloatField(default=0.0)
    precision = models.FloatField(default=0.0)
    recall = models.FloatField(default=0.0)
    f1_score = models.FloatField(default=0.0)
    training_samples = models.IntegerField(default=0)
    training_data_size = models.IntegerField(default=0)
    feature_count=models.IntegerField(default=0)
    hyperparameters=models.JSONField(default=dict)
    evaluation_metrics= models.JSONField(default=dict)  # Store metrics like ROC-AUC, confusion matrix, etc.
    # Feature importance (JSON field)
    feature_importance = models.JSONField(default=dict)

    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]


class ThreatDetection(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    # Enhanced threat types based on CIC-IDS2017 attacks
    THREAT_TYPES = [
        ("benign", "Benign Traffic"),
        ("ddos", "DDoS Attack"),
        ("port_scan", "Port Scan"),
        ("brute_force", "Brute Force"),
        ("web_attack_bruteforce", "Web Attack - Brute Force"),
        ("web_attack_xss", "Web Attack - XSS"),
        ("web_attack_sql_injection", "Web Attack - SQL Injection"),
        ("infiltration", "Infiltration"),
        ("bot", "Bot"),
        ("dos_hulk", "DoS Hulk"),
        ("dos_goldeneye", "DoS GoldenEye"),
        ("dos_slowhttptest", "DoS Slow HTTP Test"),
        ("dos_slowloris", "DoS Slowloris"),
        ("heartbleed", "Heartbleed"),
        ("ssh_patator", "SSH-Patator"),
        ("ftp_patator", "FTP-Patator"),
        ("ml_anomaly", "ML Anomaly Detection"),
        ("behavioral_anomaly", "Behavioral Anomaly"),
    ]

    pcap_file = models.ForeignKey(
        PcapFile, on_delete=models.CASCADE, related_name="threats"
    )
    connection = models.ForeignKey(
        NetworkConnection,
        on_delete=models.CASCADE,
        related_name="threats",
        null=True,
        blank=True,
    )
    threat_type = models.CharField(max_length=50, choices=THREAT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    confidence_score = models.FloatField()
    packet_count = models.IntegerField()
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    description = models.TextField()
    raw_data = models.JSONField(default=dict)

    # ML model that detected this threat
    detected_by_model = models.ForeignKey(
        MLModel, on_delete=models.SET_NULL, null=True, blank=True
    )

    class Meta:
        ordering = ["-first_seen"]
        indexes = [
            models.Index(fields=["threat_type", "severity"]),
            models.Index(fields=["source_ip"]),
            models.Index(fields=["first_seen"]),
        ]


class AnalysisResult(models.Model):
    pcap_file = models.OneToOneField(
        PcapFile, on_delete=models.CASCADE, related_name="analysis_result"
    )
    total_packets = models.IntegerField()
    total_bytes = models.BigIntegerField()
    duration = models.FloatField()
    protocol_distribution = models.JSONField(default=dict)
    top_sources = models.JSONField(default=list)
    top_destinations = models.JSONField(default=list)
    timeline_data = models.JSONField(default=list)
    analysis_duration = models.FloatField()

    # Enhanced ML analysis results
    ml_analysis = models.JSONField(default=dict)
    threat_analysis = models.JSONField(default=dict)

    # Traffic statistics
    benign_flows = models.IntegerField(default=0)
    malicious_flows = models.IntegerField(default=0)
    attack_type_distribution = models.JSONField(default=dict)

    # Performance metrics
    flows_per_second = models.FloatField(default=0.0)
    bytes_per_second = models.FloatField(default=0.0)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["created_at"]),
        ]


class NetworkStatistics(models.Model):
    """Store aggregated network statistics for dashboard"""

    pcap_file = models.ForeignKey(
        PcapFile, on_delete=models.CASCADE, related_name="statistics"
    )

    # Time-based statistics
    time_bucket = models.DateTimeField()  # 1-minute buckets

    # Traffic volume
    packet_count = models.IntegerField(default=0)
    byte_count = models.BigIntegerField(default=0)
    flow_count = models.IntegerField(default=0)

    # Protocol distribution
    tcp_packets = models.IntegerField(default=0)
    udp_packets = models.IntegerField(default=0)
    icmp_packets = models.IntegerField(default=0)
    other_packets = models.IntegerField(default=0)

    # Threat statistics
    benign_flows = models.IntegerField(default=0)
    malicious_flows = models.IntegerField(default=0)
    high_confidence_threats = models.IntegerField(default=0)

    # Top talkers
    top_source_ips = models.JSONField(default=list)
    top_destination_ips = models.JSONField(default=list)
    top_ports = models.JSONField(default=list)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["time_bucket"]
        unique_together = ["pcap_file", "time_bucket"]
        indexes = [
            models.Index(fields=["time_bucket"]),
            models.Index(fields=["pcap_file", "time_bucket"]),
        ]
