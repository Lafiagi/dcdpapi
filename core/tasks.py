from celery import shared_task
from django.utils import timezone
from core.models import PcapFile, NetworkConnection, ThreatDetection, AnalysisResult
from core.ml_analyzer import PcapAnalyzer
import logging

logger = logging.getLogger(__name__)


@shared_task
def analyze_pcap_file(pcap_file_id):
    try:
        pcap_file = PcapFile.objects.get(id=pcap_file_id)
        pcap_file.status = "analyzing"
        pcap_file.analysis_started_at = timezone.now()
        pcap_file.save()

        # Initialize enhanced analyzer
        print(f"Starting analysis for {pcap_file.filename}")
        analyzer = PcapAnalyzer()
        print(f"Ended analysis for {pcap_file.filename}")

        # Perform analysis
        print(f"\n\nGetting analysis results for {pcap_file.filename}\n\n")
        analysis_results = analyzer.analyze_pcap(pcap_file)
        print(f"\n\nGotten analysis results for {analysis_results}\n\n")
        # Save network connections with enhanced features
        # connections_data = analysis_results.get("connections", [])
        # connections = []

        # for conn_data in connections_data:
        #     connection = NetworkConnection(
        #         pcap_file=pcap_file,
        #         source_ip=conn_data["source_ip"],
        #         destination_ip=conn_data["destination_ip"],
        #         source_port=conn_data["source_port"],
        #         destination_port=conn_data["destination_port"],
        #         protocol=conn_data["protocol"],
        #         bytes_transferred=conn_data["bytes"],
        #         packets_count=conn_data["packets"],
        #         timestamp=conn_data["timestamp"],
        #         duration=conn_data.get("duration", 0.0),
        #         # Enhanced ML features
        #         avg_packet_size=conn_data.get("avg_packet_size", 0.0),
        #         std_packet_size=conn_data.get("std_packet_size", 0.0),
        #         avg_inter_arrival=conn_data.get("avg_inter_arrival", 0.0),
        #         std_inter_arrival=conn_data.get("std_inter_arrival", 0.0),
        #         unique_tcp_flags=conn_data.get("unique_tcp_flags", 0),
        #         syn_count=conn_data.get("syn_count", 0),
        #         rst_count=conn_data.get("rst_count", 0),
        #         bytes_per_second=conn_data.get("bytes_per_second", 0.0),
        #         packets_per_second=conn_data.get("packets_per_second", 0.0),
        #     )
        #     connections.append(connection)

        # NetworkConnection.objects.bulk_create(connections, batch_size=1000)

        # # Save threat detections
        # threats_data = analysis_results.get("threats", [])
        # threats = []

        # for threat_data in threats_data:
        #     threat = ThreatDetection(
        #         pcap_file=pcap_file,
        #         threat_type=threat_data["type"],
        #         severity=threat_data["severity"],
        #         source_ip=threat_data["source_ip"],
        #         destination_ip=threat_data["destination_ip"],
        #         confidence_score=threat_data["confidence"],
        #         packet_count=threat_data["packet_count"],
        #         first_seen=threat_data["first_seen"],
        #         last_seen=threat_data["last_seen"],
        #         description=threat_data["description"],
        #         raw_data=threat_data.get("raw_data", {}),
        #     )
        #     threats.append(threat)

        # ThreatDetection.objects.bulk_create(threats, batch_size=100)

        # # Save enhanced analysis result summary
        # summary = analysis_results["summary"]
        # AnalysisResult.objects.create(
        #     pcap_file=pcap_file,
        #     total_packets=summary["total_packets"],
        #     total_bytes=summary["total_bytes"],
        #     duration=summary["duration"],
        #     protocol_distribution=summary["protocols"],
        #     top_sources=summary["top_sources"],
        #     top_destinations=summary["top_destinations"],
        #     timeline_data=summary["timeline"],
        #     analysis_duration=summary["analysis_time"],
        #     # Enhanced ML analysis results
        #     ml_analysis=summary.get("ml_analysis", {}),
        #     threat_analysis=summary.get("threat_analysis", {}),
        # )

        # # Update status
        # pcap_file.status = "completed"
        # pcap_file.analysis_completed_at = timezone.now()
        # pcap_file.save()

        logger.info(f"Successfully analyzed PCAP file: {pcap_file.filename}")

        # Log ML analysis statistics
        # ml_stats = summary.get("ml_analysis", {})
        # threat_stats = summary.get("threat_analysis", {})

        # logger.info(
        #     f"ML Analysis - Features: {ml_stats.get('features_used', 0)}, "
        #     f"Connections: {ml_stats.get('connections_analyzed', 0)}"
        # )
        # logger.info(
        #     f"Threats Found - Total: {threat_stats.get('total_threats', 0)}, "
        #     f"Critical: {threat_stats.get('critical_threats', 0)}, "
        #     f"High: {threat_stats.get('high_threats', 0)}"
        # )

    except Exception as e:
        logger.error(f"Error analyzing PCAP file {pcap_file_id}: {str(e)}")
        try:
            pcap_file = PcapFile.objects.get(id=pcap_file_id)
            pcap_file.status = "failed"
            pcap_file.error_message = str(e)
            pcap_file.save()
        except Exception as save_error:
            logger.error(f"Error updating failed status: {str(save_error)}")
