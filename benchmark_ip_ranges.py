#!/usr/bin/env python3
"""
Benchmark script to test IP range lookup performance.

Compares the old O(n) approach vs the new O(log n) binary search approach.
"""

import time
import random
import sys
import os
import ipaddress

# Add the cloudfinderweb to the path
sys.path.insert(0, os.path.abspath('.'))

from cloudfinderweb.app.models.ip_range import IPRangeTree, IPRangeInfo


class OldIPRangeTree:
    """
    Original O(n) implementation for comparison.
    """

    def __init__(self):
        self.ranges = {}  # {network_obj: IPRangeInfo}

    def add(self, cidr: str, info: IPRangeInfo) -> bool:
        try:
            network = ipaddress.ip_network(cidr)
            self.ranges[network] = info
            return True
        except ValueError:
            return False

    def lookup(self, ip: str) -> list:
        results = []
        try:
            ip_obj = ipaddress.ip_address(ip)

            for network, info in self.ranges.items():
                if ip_obj in network:
                    results.append({
                        "network": str(network),
                        "info": info.to_dict()
                    })

            return results
        except ValueError:
            return []

    def count(self) -> int:
        return len(self.ranges)


def generate_test_ranges(count: int) -> list:
    """Generate test IP ranges for benchmarking."""
    ranges = []

    # Generate IPv4 ranges
    for _ in range(count // 2):
        # Generate random network
        base_ip = random.randint(0x01000000, 0xFEFFFFFF)  # Avoid reserved ranges
        prefix = random.randint(8, 30)  # Random prefix length

        ip = ipaddress.IPv4Address(base_ip)
        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)

        ranges.append({
            "cidr": str(network),
            "info": IPRangeInfo(
                description=f"Test range {len(ranges)}",
                region=f"region-{random.randint(1, 10)}",
                service=f"service-{random.randint(1, 5)}",
                ip_type=4
            )
        })

    # Generate IPv6 ranges
    for _ in range(count // 2):
        # Generate random IPv6 network
        base_ip = random.getrandbits(128)
        prefix = random.randint(32, 64)

        ip = ipaddress.IPv6Address(base_ip)
        network = ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False)

        ranges.append({
            "cidr": str(network),
            "info": IPRangeInfo(
                description=f"Test range {len(ranges)}",
                region=f"region-{random.randint(1, 10)}",
                service=f"service-{random.randint(1, 5)}",
                ip_type=6
            )
        })

    return ranges


def generate_test_ips(count: int) -> list:
    """Generate test IP addresses for lookup benchmarking."""
    ips = []

    # Generate IPv4 addresses
    for _ in range(count // 2):
        ip = ipaddress.IPv4Address(random.randint(0x01000000, 0xFEFFFFFF))
        ips.append(str(ip))

    # Generate IPv6 addresses
    for _ in range(count // 2):
        ip = ipaddress.IPv6Address(random.getrandbits(128))
        ips.append(str(ip))

    return ips


def benchmark_loading(ranges: list, tree_class, name: str):
    """Benchmark the loading performance."""
    print(f"\n=== {name} Loading Benchmark ===")

    tree = tree_class()
    start_time = time.time()

    for range_data in ranges:
        tree.add(range_data["cidr"], range_data["info"])

    end_time = time.time()
    load_time = end_time - start_time

    print(f"Loaded {tree.count()} ranges in {load_time:.4f} seconds")
    print(f"Loading rate: {tree.count() / load_time:.0f} ranges/second")

    return tree, load_time


def benchmark_lookups(tree, test_ips: list, name: str):
    """Benchmark the lookup performance."""
    print(f"\n=== {name} Lookup Benchmark ===")

    # Warm up
    for ip in test_ips[:10]:
        tree.lookup(ip)

    start_time = time.time()
    total_matches = 0

    for ip in test_ips:
        matches = tree.lookup(ip)
        total_matches += len(matches)

    end_time = time.time()
    lookup_time = end_time - start_time

    print(f"Performed {len(test_ips)} lookups in {lookup_time:.4f} seconds")
    print(f"Lookup rate: {len(test_ips) / lookup_time:.0f} lookups/second")
    print(f"Average lookup time: {lookup_time * 1000 / len(test_ips):.2f} ms")
    print(f"Total matches found: {total_matches}")

    return lookup_time


def main():
    """Run the benchmark."""
    print("IP Range Lookup Performance Benchmark")
    print("=" * 50)

    # Configuration
    NUM_RANGES = 10000  # Number of IP ranges to test with
    NUM_LOOKUPS = 1000  # Number of IP lookups to test

    print(f"Generating {NUM_RANGES} test IP ranges...")
    test_ranges = generate_test_ranges(NUM_RANGES)

    print(f"Generating {NUM_LOOKUPS} test IP addresses...")
    test_ips = generate_test_ips(NUM_LOOKUPS)

    # Benchmark old implementation
    old_tree, old_load_time = benchmark_loading(test_ranges, OldIPRangeTree, "Old O(n)")
    old_lookup_time = benchmark_lookups(old_tree, test_ips, "Old O(n)")

    # Benchmark new implementation
    new_tree, new_load_time = benchmark_loading(test_ranges, IPRangeTree, "New O(log n)")
    new_lookup_time = benchmark_lookups(new_tree, test_ips, "New O(log n)")

    # Performance comparison
    print(f"\n=== Performance Comparison ===")
    print(f"Loading speedup: {old_load_time / new_load_time:.2f}x")
    print(f"Lookup speedup: {old_lookup_time / new_lookup_time:.2f}x")

    if new_lookup_time < old_lookup_time:
        improvement = ((old_lookup_time - new_lookup_time) / old_lookup_time) * 100
        print(f"Lookup performance improved by {improvement:.1f}%")
    else:
        regression = ((new_lookup_time - old_lookup_time) / old_lookup_time) * 100
        print(f"Lookup performance regressed by {regression:.1f}%")

    # Test correctness
    print(f"\n=== Correctness Test ===")
    print("Testing that both implementations return the same results...")

    mismatch_count = 0
    for i, ip in enumerate(test_ips[:100]):  # Test first 100 IPs
        old_results = old_tree.lookup(ip)
        new_results = new_tree.lookup(ip)

        # Sort results for comparison
        old_networks = sorted([r["network"] for r in old_results])
        new_networks = sorted([r["network"] for r in new_results])

        if old_networks != new_networks:
            mismatch_count += 1
            if mismatch_count <= 3:  # Show first few mismatches
                print(f"MISMATCH for {ip}:")
                print(f"  Old: {old_networks}")
                print(f"  New: {new_networks}")

    if mismatch_count == 0:
        print("✓ All lookups match between old and new implementations")
    else:
        print(f"✗ {mismatch_count} mismatches found out of 100 test cases")


if __name__ == '__main__':
    main()