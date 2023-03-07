from caida_datasets import PrefixToAS

from argparse import ArgumentParser
from collections import defaultdict
from dateutil import parser
from functools import reduce
from pathlib import Path
from typing import Any, Dict

import hashlib
import json
import os


def read_fingerprint(file_path: Path) -> Dict[str, Any]:
    """
    Read a fingerprint from a Path and parses the json to a dict.
    :param file_path: Path to fingerprint file.
    :return: Dict containing the parsed fingerprint.
    """
    with open(file_path, 'r') as f:
        return json.load(f)


def write_fingerprint(file_path: Path, file_contents: Dict[str, Any] | list[Dict[str, Any]]):
    """
    Write a fingerprint or a list of fingerprints to a specific file location.
    :param file_path: Path to the fingerprint file.
    :param file_contents: Object containing the fingerprint details.
    """
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as file:
        json.dump(file_contents, file, indent=4)


def weighted_avg(left_value: float, left_weight: int, right_value: float, right_weight: int) -> float:
    """
    Compute the weighted average of two values based on their weights.
    """
    if left_weight + right_weight == 0:
        return 0

    weighted_sum = left_value * left_weight + right_value * right_weight
    return round(weighted_sum / (left_weight + right_weight), 3)


def weighted_dict(left_dict: Dict[str, float], left_weight: int, right_dict: Dict[str, float], right_weight: int) -> Dict[str, float]:
    """
    Compute the weighted average for each key present in two dictionaries.
    For example:
    left = {a: 0.5, b: 0.5}, weight = 200
    right = {a: 0.3, b: 0.7}, weight = 300

    output = {
        a: (0.5 * 200 + 0.3 * 300) / 500 = 0.38
        b: (0.5 * 200 + 0.7 * 300) / 500 = 0.62
    }
    """
    out_dict = {}

    for key in set(left_dict.keys()).union(set(right_dict.keys())):
        out_dict[key] = weighted_avg(
            left_dict.get(key, 0),
            left_weight,
            right_dict.get(key, 0),
            right_weight
        )

    return out_dict


def merge_dict_if_present(merged_vector: Dict[str, Any], x: Dict[str, Any], y: Dict[str, Any], key: str, default_value: Any):
    """
    Merge dictionary values that represented the distribution of different parameters in the attack.
    :param merged_vector: Output attack vector.
    :param x: First attack vector to be merged.
    :param y: Second attack vector to be merged.
    :param key: Name of the parameter that needs to be merged.
    :param default_value: In case both vectors do not contain this parameter, this default value is used.
    """
    if (key in x and type(x[key]) == dict) and (key in y and type(y[key]) == dict):
        # If they are both dictionaries then compute the weighted contribution of each vectors.
        merged_vector[key] = weighted_dict(
            x[key],
            x["nr_packets"],
            y[key],
            y["nr_packets"]
        )
    elif (key in x and x[key] == "random") or (key in y and y[key] == "random"):
        merged_vector[key] = "random"
    elif key in x:
        merged_vector[key] = x[key]
    elif key in y:
        merged_vector[key] = y[key]
    else:
        merged_vector[key] = default_value


def merge_attack_vectors(x: Dict[str, Any], y: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two attack vectors together, similarly to `merge_fingerprints` this function is used as the reduction operator.
    """
    merged_vector = {
        "service": x["service"],
        "protocol": x["protocol"],
        "source_port": x["source_port"],
        "fraction_of_attack": 0.0,
        "nr_packets": x["nr_packets"] + y["nr_packets"],
        "nr_megabytes": x["nr_megabytes"] + y["nr_megabytes"],
        "avg_bps": int(weighted_avg(x["avg_bps"], x["duration_seconds"], y["avg_bps"], y["duration_seconds"])),
        "avg_pps": int(weighted_avg(x["avg_pps"], x["duration_seconds"], y["avg_pps"], y["duration_seconds"])),
        "avg_Bpp": int(weighted_avg(x["avg_Bpp"], x["nr_packets"], y["avg_Bpp"], y["nr_packets"])),
        "peak_bps": max(x["peak_bps"], y["peak_bps"]),
        "peak_pps": max(x["peak_pps"], y["peak_pps"]),
        "peak_Bpp": max(x["peak_Bpp"], y["peak_Bpp"]),
        "time_start": min(parser.parse(x["time_start"]), parser.parse(y["time_start"])).isoformat(),
        "duration_seconds": x["duration_seconds"] + y["duration_seconds"],
        "source_ips": list(set(x["source_ips"]).union(set(y["source_ips"]))),
    }

    if "nr_flows" in x and "nr_flows" in y:
        merged_vector["nr_flows"] = x["nr_flows"] + y["nr_flows"]

    merge_dict_if_present(merged_vector, x, y, "destination_ports", "random")
    merge_dict_if_present(merged_vector, x, y, "tcp_flags", None)
    merge_dict_if_present(merged_vector, x, y, "ethernet_type", None)
    merge_dict_if_present(merged_vector, x, y, "frame_len", None)
    merge_dict_if_present(merged_vector, x, y, "fragmentation_offset", None)
    merge_dict_if_present(merged_vector, x, y, "ttl", None)
    merge_dict_if_present(merged_vector, x, y, "dns_query_name", None)
    merge_dict_if_present(merged_vector, x, y, "dns_query_type", None)
    merge_dict_if_present(merged_vector, x, y, "http_uri", None)
    merge_dict_if_present(merged_vector, x, y, "http_method", None)
    merge_dict_if_present(merged_vector, x, y, "http_user_agent", None)
    merge_dict_if_present(merged_vector, x, y, "ntp_requestcode", None)
    merge_dict_if_present(merged_vector, x, y, "icmp_type", None)

    return merged_vector


def merge_normal_traffic(x: Dict[str, Any], y: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge normal traffic statistics using the same procedure applied to fingerprints.
    """
    merged_traffic = {
        "total_packets": x["total_packets"] + y["total_packets"],
        "total_megabytes": x["total_megabytes"] + y["total_megabytes"],
        "avg_bps": int(weighted_avg(x["avg_bps"], x["attack_duration"], y["avg_bps"], y["attack_duration"])),
        "avg_pps": int(weighted_avg(x["avg_pps"], x["attack_duration"], y["avg_pps"], y["attack_duration"])),
        "avg_Bpp": int(weighted_avg(x["avg_Bpp"], x["total_packets"], y["avg_Bpp"], y["total_packets"])),
        "peak_bps": max(x["peak_bps"], y["peak_bps"]),
        "peak_pps": max(x["peak_pps"], y["peak_pps"]),
        "peak_Bpp": max(x["peak_Bpp"], y["peak_Bpp"]),
    }

    if "total_flows" in x and "total_flows" in y:
        merged_traffic["total_flows"] = x["total_flows"] + y["total_flows"]

    merge_dict_if_present(merged_traffic, x, y, "source_port", "random")
    merge_dict_if_present(merged_traffic, x, y, "destination_ports", "random")
    merge_dict_if_present(merged_traffic, x, y, "protocol", "random")

    return merged_traffic


def merge_fingerprints(x: Dict[str, Any], y: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two fingerprints together, depending on the parameter a different operation is applied.
    For example:
    - SUM: total_packets, total_megabytes
    - AVG: avg_bps, avg_pps, avg_Bpp
    - MAX: peak_bps, peak_pps, peak_Bpp

    This function is used as the reduction operator.
    """
    time_start = min(parser.parse(x["time_start"]), parser.parse(y["time_start"]))
    time_end = max(parser.parse(x["time_end"]), parser.parse(y["time_end"]))
    merged_attack = {
        "target": x["target"],
        "duration_seconds": (time_end - time_start).seconds,
        "tags": list(set(x["tags"]).union(set(y["tags"]))),
        "time_start": time_start.isoformat(),
        "time_end": time_end.isoformat(),
        "total_packets": x["total_packets"] + y["total_packets"],
        "total_megabytes": x["total_megabytes"] + y["total_megabytes"],
        "avg_bps": int(weighted_avg(x["avg_bps"], x["duration_seconds"], y["avg_bps"], y["duration_seconds"])),
        "avg_pps": int(weighted_avg(x["avg_pps"], x["duration_seconds"], y["avg_pps"], y["duration_seconds"])),
        "avg_Bpp": int(weighted_avg(x["avg_Bpp"], x["total_packets"], y["avg_Bpp"], y["total_packets"])),
        "peak_bps": max(x["peak_bps"], y["peak_bps"]),
        "peak_pps": max(x["peak_pps"], y["peak_pps"]),
        "peak_Bpp": max(x["peak_Bpp"], y["peak_Bpp"]),
    }

    if "total_flows" in x and "total_flows" in y:
        merged_attack["total_flows"] = x["total_flows"] + y["total_flows"]

    if "normal_traffic" in x and "normal_traffic" in y:
        merged_attack["normal_traffic"] = merge_normal_traffic(x["normal_traffic"], y["normal_traffic"])
        merged_attack["normal_traffic"]["attack_duration"] = merged_attack["duration_seconds"]

    vectorsMap = defaultdict(list)
    for attack_vector in x["attack_vectors"] + y["attack_vectors"]:
        # Attack vectors are considered to be merged together if they have the same service, protocol, and source port.
        vectorsMap[(attack_vector["service"], attack_vector["protocol"], attack_vector["source_port"])].append(attack_vector)
    merged_attack["attack_vectors"] = [reduce(merge_attack_vectors, vectors) for vectors in vectorsMap.values()]

    ips = set()
    for attack_vector in merged_attack["attack_vectors"]:
        ips = ips.union(attack_vector["source_ips"])
        if attack_vector["service"] != "Fragmented IP packets":
            attack_vector["fraction_of_attack"] = attack_vector["nr_packets"] / merged_attack["total_packets"]
    merged_attack["total_ips"] = len(ips)

    return merged_attack


def anonymize_ips(attack_vector: Dict[str, Any]) -> Dict[str, Any]:
    """
    Anonymize the IP addresses contained in the attack vector using CAIDA routeviews dataset.
    :param attack_vector: Original attack vector.
    :return: Anonymized attack vector.
    """
    time_start = parser.parse(attack_vector["time_start"])
    prefix_to_as = PrefixToAS(time_start.year, time_start.month, time_start.day).download()
    attack_vector["source_ips"] = [prefix_to_as.lookup(ip) for ip in attack_vector["source_ips"]]
    return attack_vector


def read_and_merge(filename: str, data_folder: Path):
    """
    Read all fingerprints found in `data_folder`, merge them together, and output the result to `out/{filename}.json`.
    :param filename: Name of the output fingerprint file.
    :param data_folder: Path to folder containing all fingerprints.
    """
    fingerprint_files = [
        read_fingerprint(Path(data_dir) / file)
        for data_dir, _, files in os.walk(data_folder)
        for file in files
        if file.endswith('.json')
    ]

    # Apply a reduce operation to merge the fingerprints together
    reduced_attack = reduce(merge_fingerprints, fingerprint_files)
    reduced_attack["attack_vectors"] = [anonymize_ips(attack_vector) for attack_vector in reduced_attack["attack_vectors"]]
    reduced_attack["key"] = hashlib.md5((str(reduced_attack)).encode()).hexdigest()

    write_fingerprint(Path(f"out/{filename}.json"), reduced_attack)
    write_fingerprint(Path(f"intermediate_fingeprints/{filename}.json"), fingerprint_files)


if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-f', '--fingerprint', type=Path, help='Fingerprints folder', required=True, dest='fingerprint_folder')
    arg_parser.add_argument('-o', '--output', type=str, help='Output file', required=True, dest='output')
    args = arg_parser.parse_args()
    read_and_merge(args.output, args.fingerprint_folder)
