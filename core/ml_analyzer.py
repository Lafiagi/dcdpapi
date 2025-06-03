import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any
import statistics
import json
import os
from django.utils import timezone
from django.utils import timezone
from core.models import (
    PcapFile,
    NetworkConnection,
    ThreatDetection,
    AnalysisResult,
    MLModel,
    NetworkStatistics,
)

logger = logging.getLogger(__name__)


def convert_numpy_types(obj):
    """Convert numpy types to native Python types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_numpy_types(item) for item in obj)
    return obj


CIC_IDS_MODEL_PATH = "dcdp/cic_ids_model.pkl"


class PcapAnalyzer:
    """Main PCAP analysis engine with ML integration"""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_columns = None
        self.load_cic_ids_model()

    def load_cic_ids_model(self):
        """Load the CIC-IDS2017 trained model"""
        try:
            model_data = joblib.load(CIC_IDS_MODEL_PATH)
            if isinstance(model_data, dict):
                self.model = model_data.get("model", model_data)
                self.scaler = model_data.get("scaler")
                self.feature_columns = model_data.get("feature_columns")
            else:
                self.model = model_data
            logger.info(f"Loaded CIC-IDS2017 model from {CIC_IDS_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to load CIC-IDS2017 model: {e}")

    def analyze_pcap(self, pcap_file_obj: PcapFile) -> bool:
        """Main analysis function using CIC-IDS2017 model"""
        try:
            pcap_file_obj.status = "analyzing"
            pcap_file_obj.analysis_started_at = timezone.now()
            pcap_file_obj.save(update_fields=["status", "analysis_started_at"])

            file_path = pcap_file_obj.file.path
            packets = rdpcap(file_path)
            logger.info(f"Loaded {len(packets)} packets from {pcap_file_obj.filename}")

            flows = self.extract_flows(packets)
            logger.info(f"Extracted {len(flows)} flows")

            flow_features = self.calculate_flow_features(flows)
            connections = self.store_connections(pcap_file_obj, flow_features)

            # --- ML Analysis using CIC-IDS2017 model ---
            ml_results = self.perform_ml_analysis(connections)

            # Detect threats (optional: you can use rule-based as well)
            threats = self.detect_threats(pcap_file_obj, connections, ml_results)

            self.generate_statistics(pcap_file_obj, connections, flows)
            self.create_analysis_result(
                pcap_file_obj, packets, flows, ml_results, threats
            )

            pcap_file_obj.status = "completed"
            pcap_file_obj.analysis_completed_at = timezone.now()
            pcap_file_obj.save(update_fields=["status", "analysis_completed_at"])
            logger.info(f"Analysis completed for {pcap_file_obj.filename}")
            return True

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            pcap_file_obj.status = "failed"
            pcap_file_obj.error_message = str(e)
            pcap_file_obj.save(update_fields=["status", "error_message"])
            return False

    def extract_flows(self, packets) -> Dict:
        """Extract bidirectional flows from packets"""
        flows = defaultdict(
            lambda: {
                "packets": [],
                "start_time": None,
                "end_time": None,
                "fwd_packets": [],
                "bwd_packets": [],
            }
        )

        for packet in packets:
            if IP in packet:
                # Create flow key (bidirectional)
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                else:
                    protocol = "OTHER"
                    src_port = 0
                    dst_port = 0

                # Create bidirectional flow key
                flow_key = self.create_flow_key(
                    src_ip, dst_ip, src_port, dst_port, protocol
                )

                # Determine packet direction
                canonical_key = tuple(
                    sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"])
                )
                flow_canonical_key = f"{canonical_key[0]}-{canonical_key[1]}-{protocol}"

                if flow_canonical_key not in flows:
                    flows[flow_canonical_key] = {
                        "packets": [],
                        "start_time": packet.time,
                        "end_time": packet.time,
                        "fwd_packets": [],
                        "bwd_packets": [],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                    }

                flow = flows[flow_canonical_key]
                flow["packets"].append(packet)
                flow["end_time"] = packet.time

                # Determine packet direction based on first packet
                if not flow["fwd_packets"] and not flow["bwd_packets"]:
                    # First packet defines forward direction
                    flow["fwd_packets"].append(packet)
                    flow["primary_src"] = src_ip
                    flow["primary_dst"] = dst_ip
                else:
                    # Check if packet matches forward direction
                    if src_ip == flow["primary_src"] and dst_ip == flow["primary_dst"]:
                        flow["fwd_packets"].append(packet)
                    else:
                        flow["bwd_packets"].append(packet)

        return dict(flows)

    def create_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Create a consistent flow key"""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

    def calculate_flow_features(self, flows: Dict) -> List[Dict]:
        """Calculate CIC-IDS2017 style features for each flow"""
        flow_features = []

        for flow_key, flow_data in flows.items():
            try:
                features = self.extract_single_flow_features(flow_data)
                features["flow_key"] = flow_key
                flow_features.append(features)
            except Exception as e:
                logger.warning(f"Error extracting features for flow {flow_key}: {e}")
                continue

        return flow_features

    def extract_single_flow_features(self, flow_data: Dict) -> Dict:
        """Extract features for a single flow based on CIC-IDS2017 dataset"""
        packets = flow_data["packets"]
        fwd_packets = flow_data["fwd_packets"]
        bwd_packets = flow_data["bwd_packets"]

        if not packets:
            return {}

        # Basic flow information
        features = {
            "source_ip": flow_data.get("src_ip", ""),
            "destination_ip": flow_data.get("dst_ip", ""),
            "source_port": int(flow_data.get("src_port", 0)),  # Ensure int type
            "destination_port": int(flow_data.get("dst_port", 0)),  # Ensure int type
            "protocol": flow_data.get("protocol", ""),
            "timestamp": timezone.make_aware(
                datetime.fromtimestamp(float(flow_data["start_time"]))
            ),
        }

        # Flow duration (in microseconds)
        duration = (flow_data["end_time"] - flow_data["start_time"]) * 1_000_000
        features["flow_duration"] = int(duration)

        # Packet counts
        features["total_fwd_packets"] = len(fwd_packets)
        features["total_backward_packets"] = len(bwd_packets)

        # Packet lengths
        fwd_lengths = [len(pkt) for pkt in fwd_packets]
        bwd_lengths = [len(pkt) for pkt in bwd_packets]
        all_lengths = fwd_lengths + bwd_lengths

        features["total_length_fwd_packets"] = sum(fwd_lengths)
        features["total_length_bwd_packets"] = sum(bwd_lengths)

        # Forward packet statistics
        if fwd_lengths:
            features["fwd_packet_length_max"] = max(fwd_lengths)
            features["fwd_packet_length_min"] = min(fwd_lengths)
            features["fwd_packet_length_mean"] = float(statistics.mean(fwd_lengths))
            features["fwd_packet_length_std"] = float(
                statistics.stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0
            )
        else:
            features.update(
                {
                    "fwd_packet_length_max": 0,
                    "fwd_packet_length_min": 0,
                    "fwd_packet_length_mean": 0.0,
                    "fwd_packet_length_std": 0.0,
                }
            )

        # Backward packet statistics
        if bwd_lengths:
            features["bwd_packet_length_max"] = max(bwd_lengths)
            features["bwd_packet_length_min"] = min(bwd_lengths)
            features["bwd_packet_length_mean"] = float(statistics.mean(bwd_lengths))
            features["bwd_packet_length_std"] = float(
                statistics.stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0
            )
        else:
            features.update(
                {
                    "bwd_packet_length_max": 0,
                    "bwd_packet_length_min": 0,
                    "bwd_packet_length_mean": 0.0,
                    "bwd_packet_length_std": 0.0,
                }
            )

        # Inter-arrival times
        self.calculate_iat_features(features, fwd_packets, bwd_packets, packets)

        # TCP flags analysis
        self.calculate_tcp_features(features, fwd_packets, bwd_packets)

        # Packet statistics
        if all_lengths:
            features["min_packet_length"] = min(all_lengths)
            features["max_packet_length"] = max(all_lengths)
            features["packet_length_mean"] = float(statistics.mean(all_lengths))
            features["packet_length_std"] = float(
                statistics.stdev(all_lengths) if len(all_lengths) > 1 else 0
            )
            features["packet_length_variance"] = float(
                statistics.variance(all_lengths) if len(all_lengths) > 1 else 0
            )
            features["average_packet_size"] = features["packet_length_mean"]
        else:
            features.update(
                {
                    "min_packet_length": 0,
                    "max_packet_length": 0,
                    "packet_length_mean": 0.0,
                    "packet_length_std": 0.0,
                    "packet_length_variance": 0.0,
                    "average_packet_size": 0.0,
                }
            )

        # Flow rates
        if duration > 0:
            features["fwd_packets_per_second"] = float(
                len(fwd_packets) / (duration / 1_000_000)
            )
            features["bwd_packets_per_second"] = float(
                len(bwd_packets) / (duration / 1_000_000)
            )
        else:
            features["fwd_packets_per_second"] = 0.0
            features["bwd_packets_per_second"] = 0.0

        # Segment sizes
        features["avg_fwd_segment_size"] = features["fwd_packet_length_mean"]
        features["avg_bwd_segment_size"] = features["bwd_packet_length_mean"]

        # Additional features
        self.calculate_additional_features(features, fwd_packets, bwd_packets)

        return features

    def calculate_iat_features(
        self, features: Dict, fwd_packets: List, bwd_packets: List, all_packets: List
    ):
        """Calculate inter-arrival time features"""
        # Flow IAT
        if len(all_packets) > 1:
            flow_iats = []
            for i in range(1, len(all_packets)):
                iat = (
                    all_packets[i].time - all_packets[i - 1].time
                ) * 1_000_000  # microseconds
                flow_iats.append(int(iat))

            if flow_iats:
                features["flow_iat_mean"] = float(statistics.mean(flow_iats))
                features["flow_iat_std"] = float(
                    statistics.stdev(flow_iats) if len(flow_iats) > 1 else 0
                )
                features["flow_iat_max"] = max(flow_iats)
                features["flow_iat_min"] = min(flow_iats)
            else:
                features.update(
                    {
                        "flow_iat_mean": 0.0,
                        "flow_iat_std": 0.0,
                        "flow_iat_max": 0,
                        "flow_iat_min": 0,
                    }
                )
        else:
            features.update(
                {
                    "flow_iat_mean": 0.0,
                    "flow_iat_std": 0.0,
                    "flow_iat_max": 0,
                    "flow_iat_min": 0,
                }
            )

        # Forward IAT
        if len(fwd_packets) > 1:
            fwd_iats = []
            for i in range(1, len(fwd_packets)):
                iat = (fwd_packets[i].time - fwd_packets[i - 1].time) * 1_000_000
                fwd_iats.append(int(iat))

            features["fwd_iat_total"] = sum(fwd_iats)
            features["fwd_iat_mean"] = float(statistics.mean(fwd_iats))
            features["fwd_iat_std"] = float(
                statistics.stdev(fwd_iats) if len(fwd_iats) > 1 else 0
            )
            features["fwd_iat_max"] = max(fwd_iats)
            features["fwd_iat_min"] = min(fwd_iats)
        else:
            features.update(
                {
                    "fwd_iat_total": 0,
                    "fwd_iat_mean": 0.0,
                    "fwd_iat_std": 0.0,
                    "fwd_iat_max": 0,
                    "fwd_iat_min": 0,
                }
            )

        # Backward IAT
        if len(bwd_packets) > 1:
            bwd_iats = []
            for i in range(1, len(bwd_packets)):
                iat = (bwd_packets[i].time - bwd_packets[i - 1].time) * 1_000_000
                bwd_iats.append(int(iat))

            features["bwd_iat_total"] = sum(bwd_iats)
            features["bwd_iat_mean"] = float(statistics.mean(bwd_iats))
            features["bwd_iat_std"] = float(
                statistics.stdev(bwd_iats) if len(bwd_iats) > 1 else 0
            )
            features["bwd_iat_max"] = max(bwd_iats)
            features["bwd_iat_min"] = min(bwd_iats)
        else:
            features.update(
                {
                    "bwd_iat_total": 0,
                    "bwd_iat_mean": 0.0,
                    "bwd_iat_std": 0.0,
                    "bwd_iat_max": 0,
                    "bwd_iat_min": 0,
                }
            )

    def calculate_tcp_features(
        self, features: Dict, fwd_packets: List, bwd_packets: List
    ):
        """Calculate TCP-specific features"""
        # Initialize counters
        flag_counts = {
            "fin_flag_count": 0,
            "syn_flag_count": 0,
            "rst_flag_count": 0,
            "psh_flag_count": 0,
            "ack_flag_count": 0,
            "urg_flag_count": 0,
            "cwe_flag_count": 0,
            "ece_flag_count": 0,
        }

        fwd_psh_flags = 0
        bwd_psh_flags = 0
        fwd_urg_flags = 0
        bwd_urg_flags = 0
        fwd_header_length = 0
        bwd_header_length = 0

        # Analyze forward packets
        for pkt in fwd_packets:
            if TCP in pkt:
                tcp_layer = pkt[TCP]
                if tcp_layer.flags & 0x01:
                    flag_counts["fin_flag_count"] += 1
                if tcp_layer.flags & 0x02:
                    flag_counts["syn_flag_count"] += 1
                if tcp_layer.flags & 0x04:
                    flag_counts["rst_flag_count"] += 1
                if tcp_layer.flags & 0x08:
                    flag_counts["psh_flag_count"] += 1
                    fwd_psh_flags += 1
                if tcp_layer.flags & 0x10:
                    flag_counts["ack_flag_count"] += 1
                if tcp_layer.flags & 0x20:
                    flag_counts["urg_flag_count"] += 1
                    fwd_urg_flags += 1
                if tcp_layer.flags & 0x40:
                    flag_counts["ece_flag_count"] += 1
                if tcp_layer.flags & 0x80:
                    flag_counts["cwe_flag_count"] += 1

                fwd_header_length += tcp_layer.dataofs * 4

        # Analyze backward packets
        for pkt in bwd_packets:
            if TCP in pkt:
                tcp_layer = pkt[TCP]
                if tcp_layer.flags & 0x01:
                    flag_counts["fin_flag_count"] += 1
                if tcp_layer.flags & 0x02:
                    flag_counts["syn_flag_count"] += 1
                if tcp_layer.flags & 0x04:
                    flag_counts["rst_flag_count"] += 1
                if tcp_layer.flags & 0x08:
                    flag_counts["psh_flag_count"] += 1
                    bwd_psh_flags += 1
                if tcp_layer.flags & 0x10:
                    flag_counts["ack_flag_count"] += 1
                if tcp_layer.flags & 0x20:
                    flag_counts["urg_flag_count"] += 1
                    bwd_urg_flags += 1
                if tcp_layer.flags & 0x40:
                    flag_counts["ece_flag_count"] += 1
                if tcp_layer.flags & 0x80:
                    flag_counts["cwe_flag_count"] += 1

                bwd_header_length += tcp_layer.dataofs * 4

        # Update features
        features.update(flag_counts)
        features.update(
            {
                "fwd_psh_flags": fwd_psh_flags,
                "bwd_psh_flags": bwd_psh_flags,
                "fwd_urg_flags": fwd_urg_flags,
                "bwd_urg_flags": bwd_urg_flags,
                "fwd_header_length": fwd_header_length,
                "bwd_header_length": bwd_header_length,
            }
        )

    def calculate_additional_features(
        self, features: Dict, fwd_packets: List, bwd_packets: List
    ):
        """Calculate additional flow features"""
        # Down/Up ratio
        if features["total_length_fwd_packets"] > 0:
            features["down_up_ratio"] = float(
                features["total_length_bwd_packets"]
                / features["total_length_fwd_packets"]
            )
        else:
            features["down_up_ratio"] = 0.0

        # Bulk transfer features (simplified)
        features.update(
            {
                "fwd_byts_per_bulk_avg": 0.0,
                "fwd_pkts_per_bulk_avg": 0.0,
                "fwd_blk_rate_avg": 0.0,
                "bwd_byts_per_bulk_avg": 0.0,
                "bwd_pkts_per_bulk_avg": 0.0,
                "bwd_blk_rate_avg": 0.0,
            }
        )

        # Subflow features
        features.update(
            {
                "subflow_fwd_packets": len(fwd_packets),
                "subflow_fwd_bytes": features["total_length_fwd_packets"],
                "subflow_bwd_packets": len(bwd_packets),
                "subflow_bwd_bytes": features["total_length_bwd_packets"],
            }
        )

        # Window size features (for TCP)
        init_win_fwd = 0
        init_win_bwd = 0
        act_data_pkt_fwd = 0
        min_seg_size_forward = float("inf")

        for pkt in fwd_packets:
            if TCP in pkt:
                if init_win_fwd == 0:
                    init_win_fwd = pkt[TCP].window
                if len(pkt[TCP].payload) > 0:
                    act_data_pkt_fwd += 1
                    if len(pkt) < min_seg_size_forward:
                        min_seg_size_forward = len(pkt)

        for pkt in bwd_packets:
            if TCP in pkt and init_win_bwd == 0:
                init_win_bwd = pkt[TCP].window

        features.update(
            {
                "init_win_bytes_forward": init_win_fwd,
                "init_win_bytes_backward": init_win_bwd,
                "act_data_pkt_fwd": act_data_pkt_fwd,
                "min_seg_size_forward": (
                    min_seg_size_forward if min_seg_size_forward != float("inf") else 0
                ),
            }
        )

        # Active/Idle time features (simplified - would need more complex analysis for real implementation)
        features.update(
            {
                "active_mean": 0.0,
                "active_std": 0.0,
                "active_max": 0.0,
                "active_min": 0.0,
                "idle_mean": 0.0,
                "idle_std": 0.0,
                "idle_max": 0.0,
                "idle_min": 0.0,
            }
        )

    def store_connections(
        self, pcap_file_obj: PcapFile, flow_features: List[Dict]
    ) -> List[NetworkConnection]:
        """Store network connections in database"""
        connections = []

        for features in flow_features:
            try:
                # Convert numpy types before storing
                clean_features = convert_numpy_types(
                    {k: v for k, v in features.items() if k != "flow_key"}
                )

                connection = NetworkConnection.objects.create(
                    pcap_file=pcap_file_obj, **clean_features
                )
                connections.append(connection)
            except Exception as e:
                logger.error(f"Error storing connection: {e}")
                continue

        logger.info(f"Stored {len(connections)} network connections")
        return connections

    def perform_ml_analysis(self, connections: List[NetworkConnection]) -> dict:
        """Use the loaded CIC-IDS2017 model to classify connections as malicious/benign"""
        if not self.model or not connections:
            logger.error("CIC-IDS2017 model not loaded or no connections to analyze.")
            return {}

        # Prepare feature matrix
        feature_matrix = self.prepare_feature_matrix(connections)
        if self.scaler:
            feature_matrix = self.scaler.transform(feature_matrix)

        predictions = self.model.predict(feature_matrix)
        try:
            probabilities = self.model.predict_proba(feature_matrix)
        except Exception:
            probabilities = [
                [1.0, 0.0] if p == 0 else [0.0, 1.0] for p in predictions
            ]  # fallback

        ml_results = {"binary_predictions": []}
        for conn, pred, prob in zip(connections, predictions, probabilities):
            is_malicious = bool(pred)
            confidence = float(max(prob))
            conn.is_malicious = is_malicious
            conn.confidence_score = confidence
            conn.save()
            ml_results["binary_predictions"].append(
                {
                    "connection_id": conn.id,
                    "is_malicious": is_malicious,
                    "confidence": confidence,
                }
            )
        return ml_results

    def prepare_feature_matrix(
        self, connections: List[NetworkConnection]
    ) -> np.ndarray:
        """Prepare feature matrix for ML models with all 78 features"""

        # Complete list of 78 features in the exact order expected by the models
        feature_names = [
            "destination_port",  # 1. Missing in your original
            "flow_duration",  # 2.
            "total_fwd_packets",  # 3.
            "total_backward_packets",  # 4.
            "total_length_fwd_packets",  # 5.
            "total_length_bwd_packets",  # 6.
            "fwd_packet_length_max",  # 7.
            "fwd_packet_length_min",  # 8.
            "fwd_packet_length_mean",  # 9.
            "fwd_packet_length_std",  # 10.
            "bwd_packet_length_max",  # 11.
            "bwd_packet_length_min",  # 12.
            "bwd_packet_length_mean",  # 13.
            "bwd_packet_length_std",  # 14.
            "flow_bytes_per_second",  # 15. Missing - Flow Bytes/s
            "flow_packets_per_second",  # 16. Missing - Flow Packets/s
            "flow_iat_mean",  # 17.
            "flow_iat_std",  # 18.
            "flow_iat_max",  # 19.
            "flow_iat_min",  # 20.
            "fwd_iat_total",  # 21. Missing - Fwd IAT Total
            "fwd_iat_mean",  # 22.
            "fwd_iat_std",  # 23.
            "fwd_iat_max",  # 24.
            "fwd_iat_min",  # 25.
            "bwd_iat_total",  # 26. Missing - Bwd IAT Total
            "bwd_iat_mean",  # 27.
            "bwd_iat_std",  # 28.
            "bwd_iat_max",  # 29.
            "bwd_iat_min",  # 30.
            "fwd_psh_flags",  # 31.
            "bwd_psh_flags",  # 32.
            "fwd_urg_flags",  # 33.
            "bwd_urg_flags",  # 34.
            "fwd_header_length",  # 35.
            "bwd_header_length",  # 36.
            "fwd_packets_per_second",  # 37.
            "bwd_packets_per_second",  # 38.
            "min_packet_length",  # 39.
            "max_packet_length",  # 40.
            "packet_length_mean",  # 41.
            "packet_length_std",  # 42.
            "packet_length_variance",  # 43.
            "fin_flag_count",  # 44.
            "syn_flag_count",  # 45.
            "rst_flag_count",  # 46.
            "psh_flag_count",  # 47.
            "ack_flag_count",  # 48.
            "urg_flag_count",  # 49.
            "cwe_flag_count",  # 50.
            "ece_flag_count",  # 51.
            "down_up_ratio",  # 52.
            "average_packet_size",  # 53.
            "avg_fwd_segment_size",  # 54.
            "avg_bwd_segment_size",  # 55.
            "fwd_header_length_duplicate",  # 56. Missing - Fwd Header Length.1
            "fwd_avg_bytes_bulk",  # 57. Missing - Fwd Avg Bytes/Bulk
            "fwd_avg_packets_bulk",  # 58. Missing - Fwd Avg Packets/Bulk
            "fwd_avg_bulk_rate",  # 59. Missing - Fwd Avg Bulk Rate
            "bwd_avg_bytes_bulk",  # 60. Missing - Bwd Avg Bytes/Bulk
            "bwd_avg_packets_bulk",  # 61. Missing - Bwd Avg Packets/Bulk
            "bwd_avg_bulk_rate",  # 62. Missing - Bwd Avg Bulk Rate
            "subflow_fwd_packets",  # 63.
            "subflow_fwd_bytes",  # 64.
            "subflow_bwd_packets",  # 65.
            "subflow_bwd_bytes",  # 66.
            "init_win_bytes_forward",  # 67.
            "init_win_bytes_backward",  # 68.
            "act_data_pkt_fwd",  # 69.
            "min_seg_size_forward",  # 70.
            "active_mean",  # 71. Missing - Active Mean
            "active_std",  # 72. Missing - Active Std
            "active_max",  # 73. Missing - Active Max
            "active_min",  # 74. Missing - Active Min
            "idle_mean",  # 75. Missing - Idle Mean
            "idle_std",  # 76. Missing - Idle Std
            "idle_max",  # 77. Missing - Idle Max
            "idle_min",  # 78. Missing - Idle Min
        ]

        feature_matrix = []

        for conn in connections:
            row = []
            for feature_name in feature_names:
                # Get the value from the connection object
                value = getattr(conn, feature_name, None)

                # Handle missing features with default calculations or 0
                if value is None:
                    # Calculate missing features where possible
                    if feature_name == "destination_port":
                        value = getattr(conn, "dst_port", 0)
                    elif feature_name == "flow_bytes_per_second":
                        # Calculate: total_bytes / flow_duration
                        total_bytes = getattr(
                            conn, "total_length_fwd_packets", 0
                        ) + getattr(conn, "total_length_bwd_packets", 0)
                        duration = getattr(conn, "flow_duration", 1)
                        value = total_bytes / max(duration, 1)
                    elif feature_name == "flow_packets_per_second":
                        # Calculate: total_packets / flow_duration
                        total_packets = getattr(conn, "total_fwd_packets", 0) + getattr(
                            conn, "total_backward_packets", 0
                        )
                        duration = getattr(conn, "flow_duration", 1)
                        value = total_packets / max(duration, 1)
                    elif feature_name == "fwd_iat_total":
                        # Sum of all forward inter-arrival times
                        value = getattr(conn, "fwd_iat_mean", 0) * getattr(
                            conn, "total_fwd_packets", 1
                        )
                    elif feature_name == "bwd_iat_total":
                        # Sum of all backward inter-arrival times
                        value = getattr(conn, "bwd_iat_mean", 0) * getattr(
                            conn, "total_backward_packets", 1
                        )
                    elif feature_name == "fwd_header_length_duplicate":
                        # Duplicate of fwd_header_length
                        value = getattr(conn, "fwd_header_length", 0)
                    elif feature_name in [
                        "fwd_avg_bytes_bulk",
                        "fwd_avg_packets_bulk",
                        "fwd_avg_bulk_rate",
                        "bwd_avg_bytes_bulk",
                        "bwd_avg_packets_bulk",
                        "bwd_avg_bulk_rate",
                    ]:
                        # Bulk transfer features - often 0 for most connections
                        value = 0
                    elif feature_name in [
                        "active_mean",
                        "active_std",
                        "active_max",
                        "active_min",
                        "idle_mean",
                        "idle_std",
                        "idle_max",
                        "idle_min",
                    ]:
                        # Active/Idle timing features - often 0 for most connections
                        value = 0
                    else:
                        value = 0

                # Convert to float
                row.append(float(value) if value is not None else 0.0)

            feature_matrix.append(row)

        return np.array(feature_matrix)

    # Alternative: Use dynamic feature mapping from the model
    def prepare_feature_matrix_dynamic(
        self, connections: List[NetworkConnection], model_type: str
    ) -> np.ndarray:
        """Prepare feature matrix using the exact feature names from the trained model"""

        # Get expected features from the model (converts spaces to underscores for attribute names)
        expected_features = self.models[model_type]["feature_columns"]

        feature_matrix = []

        for conn in connections:
            row = []
            for feature_name in expected_features:
                # Convert feature name from model to attribute name
                # "Destination Port" -> "destination_port"
                attr_name = (
                    feature_name.lower()
                    .replace(" ", "_")
                    .replace("/", "_per_")
                    .replace(".", "_")
                )

                # Handle special cases
                if attr_name == "fwd_header_length_1":
                    attr_name = "fwd_header_length"  # Duplicate field
                elif attr_name == "flow_bytes_per_s":
                    # Calculate flow bytes per second
                    total_bytes = getattr(
                        conn, "total_length_fwd_packets", 0
                    ) + getattr(conn, "total_length_bwd_packets", 0)
                    duration = getattr(conn, "flow_duration", 1)
                    value = total_bytes / max(duration, 1)
                    row.append(float(value))
                    continue
                elif attr_name == "flow_packets_per_s":
                    # Calculate flow packets per second
                    total_packets = getattr(conn, "total_fwd_packets", 0) + getattr(
                        conn, "total_backward_packets", 0
                    )
                    duration = getattr(conn, "flow_duration", 1)
                    value = total_packets / max(duration, 1)
                    row.append(float(value))
                    continue

                # Get value from connection object
                value = getattr(conn, attr_name, 0)
                row.append(float(value) if value is not None else 0.0)

            feature_matrix.append(row)

        return np.array(feature_matrix)

    def detect_threats(
        self,
        pcap_file_obj: PcapFile,
        connections: List[NetworkConnection],
        ml_results: Dict,
    ) -> List[ThreatDetection]:
        """Detect threats based on ML results and rule-based detection"""
        threats = []

        # ML-based threat detection
        for pred in ml_results.get("binary_predictions", []):
            if pred["is_malicious"] and pred["confidence"] > 0.7:
                conn = NetworkConnection.objects.get(id=pred["connection_id"])

                # Determine attack type from multiclass results
                attack_type = "ml_anomaly"
                for mc_pred in ml_results.get("multiclass_predictions", []):
                    if mc_pred["connection_id"] == pred["connection_id"]:
                        attack_type = mc_pred["attack_type"]
                        break

                threat = ThreatDetection.objects.create(
                    pcap_file=pcap_file_obj,
                    connection=conn,
                    threat_type=attack_type,
                    severity=self.determine_severity(pred["confidence"], attack_type),
                    source_ip=conn.source_ip,
                    destination_ip=conn.destination_ip,
                    confidence_score=pred["confidence"],
                    packet_count=conn.total_fwd_packets + conn.total_backward_packets,
                    first_seen=conn.timestamp,
                    last_seen=conn.timestamp,
                    description=f"ML-detected {attack_type} with confidence {pred['confidence']:.2f}",
                    raw_data={"ml_prediction": pred},
                )
                threats.append(threat)

        # Rule-based threat detection
        rule_threats = self.rule_based_detection(pcap_file_obj, connections)
        threats.extend(rule_threats)

        logger.info(f"Detected {len(threats)} threats")
        return threats

    def rule_based_detection(
        self, pcap_file_obj: PcapFile, connections: List[NetworkConnection]
    ) -> List[ThreatDetection]:
        """Rule-based threat detection"""
        threats = []

        # Port scan detection
        port_scan_threats = self.detect_port_scans(pcap_file_obj, connections)
        threats.extend(port_scan_threats)

        # DDoS detection
        ddos_threats = self.detect_ddos(pcap_file_obj, connections)
        threats.extend(ddos_threats)

        # Brute force detection
        brute_force_threats = self.detect_brute_force(pcap_file_obj, connections)
        threats.extend(brute_force_threats)

        return threats

    def detect_port_scans(
        self, pcap_file_obj: PcapFile, connections: List[NetworkConnection]
    ) -> List[ThreatDetection]:
        """Detect port scanning activities"""
        threats = []

        # Group connections by source IP
        source_connections = defaultdict(list)
        for conn in connections:
            source_connections[conn.source_ip].append(conn)

        for source_ip, conns in source_connections.items():
            # Check for multiple destination ports from same source
            dest_ports = set()
            for conn in conns:
                dest_ports.add(conn.destination_port)

            # If more than 20 different ports accessed, likely port scan
            if len(dest_ports) > 20:
                threat = ThreatDetection.objects.create(
                    pcap_file=pcap_file_obj,
                    threat_type="port_scan",
                    severity="medium",
                    source_ip=source_ip,
                    destination_ip="multiple",
                    confidence_score=min(0.9, len(dest_ports) / 100),
                    packet_count=sum(
                        conn.total_fwd_packets + conn.total_backward_packets
                        for conn in conns
                    ),
                    first_seen=min(conn.timestamp for conn in conns),
                    last_seen=max(conn.timestamp for conn in conns),
                    description=f"Port scan detected: {len(dest_ports)} ports scanned",
                    raw_data={"scanned_ports": len(dest_ports)},
                )
                threats.append(threat)

        return threats

    def detect_ddos(
        self, pcap_file_obj: PcapFile, connections: List[NetworkConnection]
    ) -> List[ThreatDetection]:
        """Detect DDoS attacks"""
        threats = []

        # Group by destination IP
        dest_connections = defaultdict(list)
        for conn in connections:
            dest_connections[conn.destination_ip].append(conn)

        for dest_ip, conns in dest_connections.items():
            # Check for high volume traffic to single destination
            total_packets = sum(
                conn.total_fwd_packets + conn.total_backward_packets for conn in conns
            )
            unique_sources = len(set(conn.source_ip for conn in conns))

            # If more than 1000 packets from more than 10 sources to same destination
            if total_packets > 1000 and unique_sources > 10:
                threat = ThreatDetection.objects.create(
                    pcap_file=pcap_file_obj,
                    threat_type="ddos",
                    severity="high",
                    source_ip="multiple",
                    destination_ip=dest_ip,
                    confidence_score=min(
                        0.95, (total_packets / 10000) + (unique_sources / 100)
                    ),
                    packet_count=total_packets,
                    first_seen=min(conn.timestamp for conn in conns),
                    last_seen=max(conn.timestamp for conn in conns),
                    description=f"DDoS detected: {total_packets} packets from {unique_sources} sources",
                    raw_data={
                        "total_packets": total_packets,
                        "unique_sources": unique_sources,
                    },
                )
                threats.append(threat)

        return threats

    def detect_brute_force(
        self, pcap_file_obj: PcapFile, connections: List[NetworkConnection]
    ) -> List[ThreatDetection]:
        """Detect brute force attacks"""
        threats = []

        # Common brute force ports
        brute_force_ports = {22, 23, 21, 25, 110, 143, 993, 995, 80, 443, 3389}

        for port in brute_force_ports:
            port_connections = [
                conn for conn in connections if conn.destination_port == port
            ]

            if not port_connections:
                continue

            # Group by source IP
            source_connections = defaultdict(list)
            for conn in port_connections:
                source_connections[conn.source_ip].append(conn)

            for source_ip, conns in source_connections.items():
                # Check for multiple failed connections (high SYN count, low data transfer)
                high_syn_connections = [
                    conn
                    for conn in conns
                    if conn.syn_flag_count > 0
                    and (conn.total_length_fwd_packets + conn.total_length_bwd_packets)
                    < 1000
                ]

                if len(high_syn_connections) > 10:
                    threat = ThreatDetection.objects.create(
                        pcap_file=pcap_file_obj,
                        threat_type="brute_force",
                        severity="medium",
                        source_ip=source_ip,
                        destination_ip=conns[0].destination_ip,
                        confidence_score=min(0.8, len(high_syn_connections) / 50),
                        packet_count=sum(
                            conn.total_fwd_packets + conn.total_backward_packets
                            for conn in conns
                        ),
                        first_seen=min(conn.timestamp for conn in conns),
                        last_seen=max(conn.timestamp for conn in conns),
                        description=f"Brute force on port {port}: {len(high_syn_connections)} attempts",
                        raw_data={"port": port, "attempts": len(high_syn_connections)},
                    )
                    threats.append(threat)

        return threats

    def determine_severity(self, confidence: float, attack_type: str) -> str:
        """Determine threat severity based on confidence and attack type"""
        high_severity_attacks = ["ddos", "infiltration", "heartbleed"]

        if attack_type in high_severity_attacks:
            return "critical" if confidence > 0.8 else "high"
        elif confidence > 0.9:
            return "high"
        elif confidence > 0.7:
            return "medium"
        else:
            return "low"

    def generate_statistics(
        self, pcap_file_obj: PcapFile, connections: List[NetworkConnection], flows: Dict
    ):
        """Generate network statistics for dashboard"""
        if not connections:
            return

        # Time-based statistics (1-minute buckets)
        time_buckets = defaultdict(
            lambda: {
                "packet_count": 0,
                "byte_count": 0,
                "flow_count": 0,
                "tcp_packets": 0,
                "udp_packets": 0,
                "icmp_packets": 0,
                "other_packets": 0,
                "benign_flows": 0,
                "malicious_flows": 0,
                "high_confidence_threats": 0,
                "source_ips": set(),
                "dest_ips": set(),
                "ports": defaultdict(int),
            }
        )

        for conn in connections:
            # Round timestamp to minute
            time_bucket = conn.timestamp.replace(second=0, microsecond=0)
            bucket = time_buckets[time_bucket]

            # Update counts
            bucket["packet_count"] += (
                conn.total_fwd_packets + conn.total_backward_packets
            )
            bucket["byte_count"] += (
                conn.total_length_fwd_packets + conn.total_length_bwd_packets
            )
            bucket["flow_count"] += 1

            # Protocol distribution
            if conn.protocol == "TCP":
                bucket["tcp_packets"] += (
                    conn.total_fwd_packets + conn.total_backward_packets
                )
            elif conn.protocol == "UDP":
                bucket["udp_packets"] += (
                    conn.total_fwd_packets + conn.total_backward_packets
                )
            elif conn.protocol == "ICMP":
                bucket["icmp_packets"] += (
                    conn.total_fwd_packets + conn.total_backward_packets
                )
            else:
                bucket["other_packets"] += (
                    conn.total_fwd_packets + conn.total_backward_packets
                )

            # Threat classification
            if conn.is_malicious:
                bucket["malicious_flows"] += 1
                if conn.confidence_score > 0.8:
                    bucket["high_confidence_threats"] += 1
            else:
                bucket["benign_flows"] += 1

            # Top talkers
            bucket["source_ips"].add(conn.source_ip)
            bucket["dest_ips"].add(conn.destination_ip)
            bucket["ports"][conn.destination_port] += 1

        # Store statistics
        for time_bucket, stats in time_buckets.items():
            NetworkStatistics.objects.create(
                pcap_file=pcap_file_obj,
                time_bucket=time_bucket,
                packet_count=stats["packet_count"],
                byte_count=stats["byte_count"],
                flow_count=stats["flow_count"],
                tcp_packets=stats["tcp_packets"],
                udp_packets=stats["udp_packets"],
                icmp_packets=stats["icmp_packets"],
                other_packets=stats["other_packets"],
                benign_flows=stats["benign_flows"],
                malicious_flows=stats["malicious_flows"],
                high_confidence_threats=stats["high_confidence_threats"],
                top_source_ips=list(stats["source_ips"])[:10],
                top_destination_ips=list(stats["dest_ips"])[:10],
                top_ports=sorted(
                    stats["ports"].items(), key=lambda x: x[1], reverse=True
                )[:10],
            )

    def create_analysis_result(
        self,
        pcap_file_obj: PcapFile,
        packets: List,
        flows: Dict,
        ml_results: Dict,
        threats: List,
    ):
        """Create analysis result summary"""
        total_packets = len(packets)
        total_bytes = sum(len(pkt) for pkt in packets)

        if packets:
            duration = packets[-1].time - packets[0].time
        else:
            duration = 0

        # Protocol distribution
        protocol_counts = Counter()
        for pkt in packets:
            if TCP in pkt:
                protocol_counts["TCP"] += 1
            elif UDP in pkt:
                protocol_counts["UDP"] += 1
            elif ICMP in pkt:
                protocol_counts["ICMP"] += 1
            else:
                protocol_counts["Other"] += 1

        # Top sources and destinations
        source_counts = Counter()
        dest_counts = Counter()
        for pkt in packets:
            if IP in pkt:
                source_counts[pkt[IP].src] += 1
                dest_counts[pkt[IP].dst] += 1

        # Timeline data (hourly buckets)
        timeline_data = []
        if packets:
            start_time = datetime.fromtimestamp(float(packets[0].time))
            end_time = datetime.fromtimestamp(float(packets[-1].time))

            current_time = start_time.replace(minute=0, second=0, microsecond=0)
            while current_time <= end_time:
                hour_packets = [
                    pkt
                    for pkt in packets
                    if current_time
                    <= datetime.fromtimestamp(float(pkt.time))
                    < current_time + timedelta(hours=1)
                ]

                timeline_data.append(
                    {
                        "timestamp": current_time.isoformat(),
                        "packet_count": len(hour_packets),
                        "byte_count": sum(len(pkt) for pkt in hour_packets),
                    }
                )

                current_time += timedelta(hours=1)

        # ML analysis summary
        ml_summary = {
            "binary_predictions": len(ml_results.get("binary_predictions", [])),
            "malicious_flows": len(
                [
                    p
                    for p in ml_results.get("binary_predictions", [])
                    if p["is_malicious"]
                ]
            ),
            "avg_confidence": (
                np.mean(
                    [p["confidence"] for p in ml_results.get("binary_predictions", [])]
                )
                if ml_results.get("binary_predictions")
                else 0
            ),
            "attack_types": Counter(
                [p["attack_type"] for p in ml_results.get("multiclass_predictions", [])]
            ),
        }

        # Threat analysis summary
        threat_summary = {
            "total_threats": len(threats),
            "severity_distribution": Counter([t.severity for t in threats]),
            "threat_types": Counter([t.threat_type for t in threats]),
            "top_threat_sources": Counter([t.source_ip for t in threats]).most_common(
                10
            ),
        }

        AnalysisResult.objects.create(
            pcap_file=pcap_file_obj,
            total_packets=total_packets,
            total_bytes=total_bytes,
            duration=duration,
            protocol_distribution=dict(protocol_counts),
            top_sources=source_counts.most_common(10),
            top_destinations=dest_counts.most_common(10),
            timeline_data=timeline_data,
            analysis_duration=(
                timezone.now() - pcap_file_obj.analysis_started_at
            ).total_seconds(),
            ml_analysis=ml_summary,
            threat_analysis=threat_summary,
            benign_flows=ml_summary.get("binary_predictions", 0)
            - ml_summary.get("malicious_flows", 0),
            malicious_flows=ml_summary.get("malicious_flows", 0),
            attack_type_distribution=dict(ml_summary.get("attack_types", {})),
            flows_per_second=len(flows) / duration if duration > 0 else 0,
            bytes_per_second=total_bytes / duration if duration > 0 else 0,
        )
