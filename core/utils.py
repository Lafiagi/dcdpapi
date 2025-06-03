import os


def validate_pcap_file(uploaded_file):
    """Validate if uploaded file is a valid PCAP file"""
    # Check file extension
    valid_extensions = [".pcap", ".pcapng", ".cap"]
    file_extension = os.path.splitext(uploaded_file.name)[1].lower()

    if file_extension not in valid_extensions:
        return False

    # Check file magic number
    try:
        file_header = uploaded_file.read(24)
        uploaded_file.seek(0)  # Reset file pointer

        # PCAP magic numbers
        pcap_magic_numbers = [
            b"\xd4\xc3\xb2\xa1",  # tcpdump pcap
            b"\xa1\xb2\xc3\xd4",  # tcpdump pcap (swapped)
            b"\x0a\x0d\x0d\x0a",  # pcapng
        ]

        for magic_number in pcap_magic_numbers:
            if file_header.startswith(magic_number):
                return True

        return False

    except Exception:
        return False
