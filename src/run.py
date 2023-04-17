from merge_fingerprints import read_and_merge

from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from netaddr import IPNetwork
from pathlib import Path
from typing import Iterator

import logging
import math
import os
import subprocess


def exec(cmd: str, sudo=False) -> str:
    """
    Execute a given bash command, returning its standard output.
    :param cmd: String containg the command to execute.
    :param sudo: Boolean flag specifying to run the command using sudo, defaults to false.
    :return: Standard output of the program execution.
    """
    cmd = f"sudo {cmd}" if sudo else cmd
    logging.debug(f"Running `{cmd}`")
    return subprocess.check_output(cmd, shell=True)


def clean_up_fingerprints(pcap: Path, is_docker: bool):
    """
    Given a PCAP file, clean up the corresponding fingerprints folder before running the algorithm.
    :param pcap: Path to the PCAP file.
    :param is_docker: Specify whether DDoS Dissector should be run using Docker or not.
    """
    fingerprints_folder = pcap.parent / 'fingerprints' if is_docker else Path('fingerprints/')
    exec(f"rm -rf {fingerprints_folder}/*", sudo=is_docker)


def get_prefix_after_split(pcap: Path) -> str:
    """
    Compute the prefix name of the PCAP files after they are split using editcap.
    The suffix .split is added to the filename, e.g., dns_amp.pcap -> dns_amp.split
    :param pcap: Path to the PCAP file.
    :return: The prefix used for the split files.
    """
    original_pcap = str(pcap).split('.')
    original_pcap.insert(-1, 'split')

    return '.'.join(original_pcap[:-1])


def after_split_pcaps(pcap: Path) -> Iterator[Path]:
    """
    Yield all files that were created during the split with editcap.
    :param pcap: Path to the PCAP file.
    """
    prefix_split_pcaps = get_prefix_after_split(pcap)
    for child in sorted(pcap.parent.iterdir()):
        if child.is_file() and str(child).startswith(prefix_split_pcaps):
            yield child


def split_and_run(args: Namespace, pcap: Path):
    """
    Split the PCAP file into smaller ones, run DDoS Dissector on them, and merge the fingerprints together.
    :param args: Arguments provided to the program.
    :param pcap: Path to the PCAP file.
    """
    capinfos = exec(f"capinfos {pcap}")
    total_packets = int([row for row in capinfos.decode('utf-8').split("\n") if 'Number of packets = ' in row].pop().split('=')[1].strip())
    pcap_size = os.path.getsize(pcap)

    nr_splits = math.ceil(pcap_size / (args.max_size * 1024 * 1024))
    packets_per_split = math.ceil(total_packets / nr_splits)
    logging.debug(f"Splitting the PCAP into {nr_splits} files ({packets_per_split} packets per split).")

    logging.debug(f"Running `rm -rf {get_prefix_after_split(pcap)}*`")
    for pcap_file in after_split_pcaps(pcap):
        os.remove(pcap_file)

    exec(f"editcap -c {packets_per_split} {pcap} {get_prefix_after_split(pcap)}.pcap")
    clean_up_fingerprints(pcap, args.docker)

    logging.debug("Running DDoS Dissector")
    for pcap_file in after_split_pcaps(pcap):
        additional_args = "--no-interactive"
        if args.targets is not None:
            target_list = " ".join(str(t) for t in args.targets)
            additional_args += f" --target {target_list}"
        if args.docker:
            exec(f"docker run --rm -i -v {pcap.resolve().parent}:/data {args.docker_image} -f /data/{pcap_file.name} {additional_args}", sudo=True)
        else:
            exec(f"python3 src/main.py -f {pcap_file} {additional_args}")

        logging.debug(f"Running rm -rf {pcap_file}")
        os.remove(pcap_file)

    logging.debug("Merging the fingerprints together.")
    read_and_merge(pcap.stem, (pcap.parent if args.docker else Path('.')) / 'fingerprints')


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', filename='combined.log', level=logging.DEBUG)

    parser = ArgumentParser()
    parser.add_argument('-p', '--pcap', type=Path, help='PCAP File', required=True, dest='pcap')
    parser.add_argument('-ms', '--max-size', type=int, help='Max file size (MB)', default=100, dest='max_size')
    parser.add_argument('-d', '--docker-image', type=str, help='Dissector Docker image.', default='dissector:1.0', dest='docker_image')
    parser.add_argument('--docker', action=BooleanOptionalAction, help='Whether to use the docker image or not')
    parser.add_argument('--target', type=IPNetwork, nargs='+', dest='targets',
                        help='Optional: target IP address or subnet of this attack')
    args = parser.parse_args()

    if args.pcap.is_dir():
        pcap_files = [pcap_file for pcap_file in sorted(args.pcap.iterdir()) if pcap_file.is_file() and str(pcap_file).endswith('.pcap')]
        for pcap_file in pcap_files:
            try:
                split_and_run(args, pcap_file)
            except:
                logging.error(pcap_file)
            finally:
                clean_up_fingerprints(pcap_file, args.docker)
                for after_split_file in after_split_pcaps(pcap_file):
                    os.remove(after_split_file)
    else:
        split_and_run(args, args.pcap)
