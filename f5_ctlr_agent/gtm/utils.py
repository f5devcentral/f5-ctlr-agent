#!/usr/bin/env python

# Copyright (c) 2018-2021 F5 Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
GTM utility functions for parsing, formatting, and config processing.

This module contains pure functions and static utilities that don't
require BIG-IP API access. These are the foundation for other GTM modules.
"""

import logging
from ipaddress import ip_address

log = logging.getLogger(__name__)


class GTMUtils:
    """Static utility methods for GTM operations."""

    @staticmethod
    def normalize_ipv4_address(value):
        """Return a stripped IPv4 address or an empty string when invalid."""
        if not isinstance(value, str):
            return ''

        normalized = value.strip()
        if not normalized:
            return ''

        try:
            parsed = ip_address(normalized)
        except ValueError:
            return ''

        if parsed.version != 4:
            return ''

        return normalized

    @staticmethod
    def apply_cluster_prefix(name, local_cluster_name=None):
        """Apply an optional cluster prefix to a GTM resource name."""
        if not name:
            return name
        if local_cluster_name:
            return "{}_{}".format(local_cluster_name, name)
        return name
    
    @staticmethod
    def _build_server_name(ip_part, local_cluster_name=None):
        """Build the GSLB server name from its components.

        This is the single place to change the naming convention.
        Current format: server_{cluster_name}_{ip}  (or server_{ip} when no cluster)

        Future format (when uid/account are added):
            server_{uid}_{cluster_name}_{account}_{ip}

        Args:
            ip_part (str): Sanitized IP string (dots/colons replaced with underscores)
            local_cluster_name (str, optional): Cluster identifier

        Returns:
            str: Assembled server name safe for BIG-IP
        """
        if local_cluster_name:
            return "server_{}_{}".format(local_cluster_name, ip_part)
        return "server_{}".format(ip_part)

    @staticmethod
    def format_server_name(dataserver_ip, local_cluster_name=None, digital_asset_id=None, namespace=None):
        """Format GSLB server name from DataServer IP.

        When digital_asset_id is provided, uses new naming format:
            server_<digital-asset-ID>_<clusterIdentifier>_<namespace>_<ip>
        Otherwise uses the standard format:
            server_<clusterIdentifier>_<ip> or server_<ip>

        Args:
            dataserver_ip (str): IP address of the data server
            local_cluster_name (str, optional): Cluster identifier
            digital_asset_id (str, optional): Cluster digital asset ID (UID)
            namespace (str, optional): Namespace/account for new naming format

        Returns:
            str: Formatted server name safe for BIG-IP
        """
        safe_ip = (dataserver_ip.replace(".", "_")
                                .replace(":", "_")
                                .replace("%", "_"))
        if digital_asset_id:
            parts = ["server", digital_asset_id]
            if local_cluster_name:
                parts.append(local_cluster_name)
            if namespace:
                parts.append(namespace)
            parts.append(safe_ip)
            return "_".join(parts)
        return GTMUtils._build_server_name(safe_ip, local_cluster_name)

    @staticmethod
    def build_wideip_name(domain_name, domain_suffix=None):
        """Construct WideIP name from domain-name and optional domain-suffix.

        Normalizes the hostname by replacing '.' with '-', then appends
        the suffix separated by '.'.

        Args:
            domain_name (str): Original hostname (e.g., 'app.example.com')
            domain_suffix (str, optional): DNS suffix (e.g., 'gslb1.fr.net.intra')

        Returns:
            str: Constructed WideIP name, e.g., 'app-example-com.gslb1.fr.net.intra'
        """
        if domain_suffix:
            normalized = domain_name.replace(".", "-")
            return "{}.{}".format(normalized, domain_suffix)
        return domain_name

    @staticmethod
    def format_pool_name(domain_name, local_cluster_name=None, digital_asset_id=None):
        """Format GTM pool name.

        Name format is composed from available identifiers in this order:
            pool-<digital_asset_id>-<clusterIdentifier>-<domain_name>
            pool-<clusterIdentifier>-<domain_name>
            pool-<domain_name>

        Incoming domain_name values that start with "pool-" or "pool_"
        are normalized by stripping that prefix before formatting.

        Args:
            domain_name (str): Domain name (e.g., 'app.example.com')
            local_cluster_name (str, optional): Cluster identifier
            digital_asset_id (str, optional): Cluster digital asset ID

        Returns:
            str: Formatted pool name
        """
        if not domain_name:
            return domain_name

        if domain_name.startswith("pool-") or domain_name.startswith("pool_"):
            normalized_domain = domain_name[5:]
        else:
            normalized_domain = domain_name

        parts = ["pool"]
        if digital_asset_id:
            parts.append(digital_asset_id)
        if local_cluster_name:
            parts.append(local_cluster_name)
        parts.append(normalized_domain)
        return "-".join(parts)

    @staticmethod
    def format_vs_name(destination, local_cluster_name=None):
        """Generate a BIG-IP-safe virtual server name from a destination.
        
        Args:
            destination (str): Destination in format "IP:PORT" (e.g., "10.0.0.1:80")
            
        Returns:
            str: Formatted VS name (e.g., "vs-10-0-0-1-80" or "vs-cluster-1-10-0-0-1-80")
        """
        safe_dest = (destination.replace(".", "-")
                                .replace(":", "-")
                                .replace("%", "-"))
        parts = ["vs"]
        if local_cluster_name:
            parts.append(local_cluster_name)
        parts.append(safe_dest)
        return "-".join(parts)
    
    @staticmethod
    def parse_member_spec(member_spec, pool_dataserver=None):
        """Centralized member spec parsing - single source of truth.
        
        Args:
            member_spec (str): Member specification in one of these formats:
                              - "dataserver|ip|port" 
                              - "ip:port" (requires pool_dataserver)
            pool_dataserver (str, optional): Default dataserver if not in member_spec
            
        Returns:
            tuple: (dataserver, member_ip, member_port, destination)
                   Returns (None, None, None, None) if parsing fails
        """
        separator = '|' if '|' in member_spec else ':'
        parts = member_spec.split(separator)

        if len(parts) == 3:
            dataserver, member_ip, member_port = parts
        elif len(parts) == 2:
            if not pool_dataserver:
                log.warning("GTM: Member '{}' has no DataServer".format(member_spec))
                return None, None, None, None
            dataserver = pool_dataserver
            member_ip, member_port = parts
        else:
            log.warning("GTM: Invalid member format: {}".format(member_spec))
            return None, None, None, None

        destination = "{}:{}".format(member_ip, member_port)
        return dataserver, member_ip, member_port, destination
    
    @staticmethod
    def convert_member_to_bigip_reference(
            member_spec, pool_dataserver=None, local_cluster_name=None,
            digital_asset_id=None, namespace=None):
        """Convert config member format to BIG-IP member reference format.

        Args:
            member_spec (str): Member specification from config
            pool_dataserver (str, optional): Default dataserver
            local_cluster_name (str, optional): Cluster identifier
            digital_asset_id (str, optional): Cluster digital asset ID
            namespace (str, optional): Namespace for new server naming format

        Returns:
            str: BIG-IP member reference "server_name:vs_name"
        """
        dataserver, member_ip, member_port, destination = \
            GTMUtils.parse_member_spec(member_spec, pool_dataserver)

        if dataserver is None:
            log.error("GTM: Cannot convert member '{}' to BIG-IP reference".format(member_spec))
            return member_spec

        vs_name = GTMUtils.format_vs_name(destination, local_cluster_name)
        server_name = GTMUtils.format_server_name(dataserver, local_cluster_name, digital_asset_id, namespace)
        member_ref = "{}:{}".format(server_name, vs_name)

        log.debug("GTM: Converted member '{}' to BIG-IP reference '{}'".format(
            member_spec, member_ref))
        return member_ref
    
    @staticmethod
    def parse_gtm_config_once(gtmConfig, partition, local_cluster_name=None, digital_asset_id=None, namespace=None):
        """Single-pass config parsing to extract ALL needed data structures.

        Args:
            gtmConfig (dict): Full GTM configuration
            partition (str): Partition to parse
            local_cluster_name (str, optional): Cluster identifier
            digital_asset_id (str, optional): Cluster digital asset ID for new server naming
            namespace (str, optional): Global namespace for server naming

        Returns:
            dict: Parsed data with keys:
                  - dataservers: set of dataserver IPs
                  - vs_inventory: dict {server_name: set((ip, vs_name, destination))}
                  - members_by_pool: dict {pool_name: set(member_refs)}
                  - all_member_refs: set of all member references
                  - all_server_names: set of all server names
        """
        result = {
            'dataservers': set(),
            'vs_inventory': {},
            'members_by_pool': {},
            'all_member_refs': set(),
            'all_server_names': set(),
        }

        if partition not in gtmConfig:
            return result

        wideips = gtmConfig[partition].get('wideIPs', [])
        if not wideips:
            return result

        for wideip in wideips:
            pools = wideip.get('pools', [])
            if not pools:
                continue

            for pool in pools:
                pool_name = GTMUtils.format_pool_name(
                    pool.get('name'), local_cluster_name, digital_asset_id)
                pool_dataserver = pool.get('DataServer')
                members = pool.get('members', [])

                if pool_name and pool_name not in result['members_by_pool']:
                    result['members_by_pool'][pool_name] = set()

                if not members:
                    continue

                for member_spec in members:
                    dataserver, member_ip, member_port, destination = \
                        GTMUtils.parse_member_spec(member_spec, pool_dataserver)

                    if dataserver is None:
                        continue

                    result['dataservers'].add(dataserver)

                    server_name = GTMUtils.format_server_name(
                        dataserver, local_cluster_name, digital_asset_id, namespace)
                    vs_name = GTMUtils.format_vs_name(
                        destination, local_cluster_name)

                    if server_name not in result['vs_inventory']:
                        result['vs_inventory'][server_name] = set()
                    result['vs_inventory'][server_name].add(
                        (member_ip, vs_name, destination))

                    member_ref = "{}:{}".format(server_name, vs_name)
                    if pool_name:
                        result['members_by_pool'][pool_name].add(member_ref)
                    result['all_member_refs'].add(member_ref)
                    result['all_server_names'].add(server_name)

        return result
    
    @staticmethod
    def find_monitor_in_config(config, partition, monitor_name):
        """Find monitor location in config structure.
        
        This is a pure utility that searches through config to find where
        a monitor is defined. Used when deleting monitors to locate them
        in the nested config structure.
        
        Args:
            config (dict): GTM config dict to search
            partition (str): BIG-IP partition name
            monitor_name (str): Name of the monitor to find
            
        Returns:
            tuple: (wideip_index, pool_index, monitor_type) or None if not found
        """
        if partition not in config or not config[partition].get('wideIPs'):
            return None
            
        for wideip_index, wideip in enumerate(config[partition]['wideIPs']):
            for pool_index, pool in enumerate(wideip.get('pools', [])):
                for monitor in pool.get('monitors', []):
                    if monitor.get('name') == monitor_name:
                        return wideip_index, pool_index, monitor.get('type')
        
        return None
    
    @staticmethod
    def pre_process_gtm(gtmConfig, disabled_availability_zones=None):
        """Pre-process GTM config to apply enhancement transformations.

        Handles the following enhancements:
        1. DNS suffix: constructs WideIP name from domain-name + domain-suffix
        2. Load balancing method: maps load-balance config to pool fallbackMode / fallback-ip
        3. Zone disablement: filters out pool members whose availability-zone is disabled
        4. Monitor send string escaping (existing behaviour)

        Args:
            gtmConfig (dict): GTM configuration to process (modified in-place)
            disabled_availability_zones (list, optional): Zone names to disable
        """
        if disabled_availability_zones is None:
            disabled_availability_zones = []
        disabled_zones_set = set(disabled_availability_zones)

        for partition in gtmConfig:
            if "wideIPs" not in gtmConfig[partition]:
                continue
            if gtmConfig[partition]['wideIPs'] is None:
                continue
            for config in gtmConfig[partition]['wideIPs']:
                # Enhancement 1: DNS suffix — build WideIP name
                domain_name = config.get('domain-name')
                domain_suffix = config.get('domain-suffix')
                if domain_name and domain_suffix:
                    config['name'] = GTMUtils.build_wideip_name(domain_name, domain_suffix)
                elif domain_name and not config.get('name'):
                    config['name'] = domain_name

                # Enhancement 3: Load balancing method — set pool fallbackMode / fallback-ip
                load_balance = config.get('load-balance')
                if load_balance:
                    method = load_balance.get('method', '')
                    explicit_fallback_ip = GTMUtils.normalize_ipv4_address(
                        load_balance.get('fallbackIp') or load_balance.get('fallback-ip', ''))
                    for pool in config.get('pools', []):
                        if method == 'Fallback IP':
                            if explicit_fallback_ip:
                                pool['fallbackMode'] = 'fallback-ip'
                                pool['fallback-ip'] = explicit_fallback_ip
                            else:
                                members = pool.get('members') or []
                                derived_fallback_ip = ''
                                if members:
                                    _, first_ip, _, _ = GTMUtils.parse_member_spec(
                                        members[0], pool.get('DataServer'))
                                    derived_fallback_ip = GTMUtils.normalize_ipv4_address(first_ip)

                                if derived_fallback_ip:
                                    pool['fallbackMode'] = 'fallback-ip'
                                    pool['fallback-ip'] = derived_fallback_ip
                                else:
                                    pool['fallbackMode'] = 'return-to-dns'
                                    pool.pop('fallback-ip', None)
                                    log.warning(
                                        "GTM: Ignoring invalid or empty fallback IP for pool %s",
                                        pool.get('name', ''))
                        elif method == 'Return to DNS':
                            pool['fallbackMode'] = 'return-to-dns'

                for pool in config.get('pools', []):
                    # Enhancement 6: Zone disablement — filter members by availability-zone
                    if disabled_zones_set:
                        member_info = pool.get('member-info')
                        if member_info:
                            enabled_info = [
                                m for m in member_info
                                if m.get('availability-zone') not in disabled_zones_set
                            ]
                            disabled_count = len(member_info) - len(enabled_info)
                            if disabled_count > 0:
                                log.info(
                                    "GTM: Zone disablement: removed %d member(s) from pool %s",
                                    disabled_count, pool.get('name', ''))
                            pool['member-info'] = enabled_info
                            pool['members'] = [
                                "{}|{}|{}".format(
                                    m['data-server'],
                                    m['pool-member-address'],
                                    m['pool-member-port'])
                                for m in enabled_info
                            ]

                    # Existing: escape monitor send strings
                    if "monitors" in pool.keys():
                        for monitor in pool['monitors']:
                            if "send" in monitor.keys():
                                monitor["send"] = monitor["send"].replace("\r", "\\r")
                                monitor["send"] = monitor["send"].replace("\n", "\\n")
    
    @staticmethod
    def is_transient_error(exception):
        """Determine if an error is transient (retriable) vs permanent (not retriable).
        
        Priority order:
          1. Exception types (isinstance checks) — most reliable
          2. HTTP status codes (if available) — structured data
          3. Permanent patterns in error messages — never retry
          4. Transient patterns in error messages — safe to retry
          5. Nested exception chain — unwrap SDK wrappers
          6. Default: transient (retry is safer than silent failure)
          
        Args:
            exception (Exception): Exception to analyze
            
        Returns:
            bool: True if error is transient and should be retried,
                  False if error is permanent
        """
        # ---- Step 1: Check exception type directly (most Pythonic) ----
        try:
            # Standard library connection errors
            if isinstance(exception, (ConnectionError, ConnectionResetError,
                                    ConnectionAbortedError, ConnectionRefusedError,
                                    BrokenPipeError, TimeoutError, OSError)):
                return True
        except NameError:
            # Python < 3.5 compatibility
            pass
        
        # ---- Step 2: Check HTTP status code if available (structured data) ----
        if hasattr(exception, 'response') and exception.response is not None:
            try:
                status_code = exception.response.status_code
                # Transient HTTP errors
                if status_code in {401, 403, 408, 429, 500, 502, 503, 504}:
                    return True
                # Permanent HTTP errors
                if status_code in {400, 404, 409, 422}:
                    return False
            except (AttributeError, TypeError):
                pass
        
        # ---- Step 3: String pattern matching (fallback) ----
        error_str = str(exception).lower()
        error_type = type(exception).__name__.lower()
        
        # Permanent patterns — NEVER retry
        PERMANENT_PATTERNS = (
            '404', 'not found', 'does not exist',
            'was not found', 'is not valid', 'is not allowed',
        )
        if any(p in error_str for p in PERMANENT_PATTERNS):
            return False
        
        # Transient string patterns
        TRANSIENT_PATTERNS = (
            # Auth (session expired, token stale)
            '401', '403',
            # Server errors
            '500', '502', '503', '504',
            # Connection errors
            'connection reset', 'connection refused',
            'connection aborted', 'broken pipe',
            'remotedisconnected', 'incompleteread',
            # Timeout
            'timeout', 'timed out',
        )
        if any(p in error_str for p in TRANSIENT_PATTERNS):
            return True
        
        # Exception type name matching (catches wrapped exceptions)
        TRANSIENT_TYPES = (
            'connectionerror', 'connectionreset', 'connectionaborted',
            'connectionrefused', 'brokenpipe', 'timeout',
        )
        if any(t in error_type for t in TRANSIENT_TYPES):
            return True
        
        # ---- Step 4: Walk nested exception chain (F5 SDK wraps errors in args) ----
        if hasattr(exception, 'args'):
            for arg in exception.args:
                if isinstance(arg, BaseException):
                    # Recursive check on nested exception
                    return GTMUtils.is_transient_error(arg)
        
        # ---- Step 5: Default to transient (retry is safer) ----
        return True
    
    @staticmethod
    def process_config(old_config, new_config):
        """Process old and new config to determine CRUD operations.
        
        Args:
            old_config (dict): Previous GTM configuration for partition
            new_config (dict): New GTM configuration for partition
            
        Returns:
            dict: CRUD operations with structure:
                  {'create': {'wideIPs': [], 'pools': [], 'monitors': []},
                   'delete': {'wideIPs': [], 'pools': [], 'monitors': []},
                   'update': {'wideIPs': [], 'pools': [], 'monitors': []}}
        """
        def _index_by_name(lst):
            return {item["name"]: item for item in lst}

        def _get_value(d, k):
            if d[k] is None:
                return dict()
            return d[k]

        def _get_crud_wide_ips(d1, d2):
            wips1 = _get_value(d1, "wideIPs")
            wips2 = _get_value(d2, "wideIPs")
            wip_set1 = set([v["name"] for v in wips1])
            wip_set2 = set([v["name"] for v in wips2])

            del_wips = list(wip_set1 - wip_set2)
            new_wips = list(wip_set2 - wip_set1)
            cur_wips = wip_set1.intersection(wip_set2)
            update_wips = []

            wip_index1 = _index_by_name(wips1)
            wip_index2 = _index_by_name(wips2)

            for wip_name in cur_wips:
                if wip_index1[wip_name] != wip_index2[wip_name]:
                    update_wips.append(wip_name)

            return new_wips, del_wips, update_wips

        def _get_crud_pools(d1, d2):
            pools1 = []
            pools2 = []
            for wip in _get_value(d1, "wideIPs"):
                pools1 += wip["pools"]
            for wip in _get_value(d2, "wideIPs"):
                pools2 += wip["pools"]

            pool_set1 = set([p["name"] for p in pools1])
            pool_set2 = set([p["name"] for p in pools2])

            new_pools = list(pool_set2 - pool_set1)
            del_pools = list(pool_set1 - pool_set2)
            cur_pools = pool_set1.intersection(pool_set2)
            update_pools = []

            pool_index1 = _index_by_name(pools1)
            pool_index2 = _index_by_name(pools2)

            for pool_name in cur_pools:
                if pool_index1[pool_name] != pool_index2[pool_name]:
                    update_pools.append(pool_name)

            return new_pools, del_pools, update_pools

        def _get_crud_monitors(d1, d2):
            pools1 = []
            pools2 = []
            for wip in _get_value(d1, "wideIPs"):
                pools1 += wip["pools"]
            for wip in _get_value(d2, "wideIPs"):
                pools2 += wip["pools"]

            monitors1, monitors2 = [], []
            for p in pools1:
                if p.get("monitors"):
                    monitors1 += p["monitors"]
            for p in pools2:
                if p.get("monitors"):
                    monitors2 += p["monitors"]

            mon_set1 = set([m["name"] for m in monitors1])
            mon_set2 = set([m["name"] for m in monitors2])

            new_mons = list(mon_set2 - mon_set1)
            del_mons = list(mon_set1 - mon_set2)
            cur_mons = mon_set1.intersection(mon_set2)
            update_mons = []

            mon_index1 = _index_by_name(monitors1)
            mon_index2 = _index_by_name(monitors2)

            for mon_name in cur_mons:
                if mon_index1[mon_name] != mon_index2[mon_name]:
                    update_mons.append(mon_name)

            return new_mons, del_mons, update_mons

        new_wips, del_wips, update_wips = _get_crud_wide_ips(old_config, new_config)
        new_pools, del_pools, update_pools = _get_crud_pools(old_config, new_config)
        new_mons, del_mons, update_mons = _get_crud_monitors(old_config, new_config)

        return {
            "create": {
                "wideIPs": new_wips,
                "pools": new_pools,
                "monitors": new_mons
            },
            "delete": {
                "wideIPs": del_wips,
                "pools": del_pools,
                "monitors": del_mons
            },
            "update": {
                "wideIPs": update_wips,
                "pools": update_pools,
                "monitors": update_mons
            }
        }
    
    @staticmethod
    def create_reverse_map(config):
        """Create reverse mapping of pools/monitors to their parent wideIPs.
        
        Args:
            config (dict): GTM config dictionary for a partition
            
        Returns:
            dict: Reverse mapping with structure:
                  {'pools': {pool_name: [wideip_names]},
                   'monitors': {monitor_name: pool_name}}
                   
        Note:
            Used during delete operations to find which wideIPs contain
            deleted pools/monitors.
        """
        rev_map = dict()
        rev_map["pools"] = dict()
        rev_map["monitors"] = dict()
        if config["wideIPs"] is None:
            di = dict()
        else:
            di = config["wideIPs"]
        for wip in di:
            wip_name = wip["name"]
            for pool in wip["pools"]:
                pool_name = pool["name"]
                try:
                    rev_map["pools"][pool_name].append(wip_name)
                except:
                    rev_map["pools"][pool_name] = [wip_name]

                try:
                    for monitor in pool["monitors"]:
                        rev_map["monitors"][monitor["name"]] = pool_name
                except:
                    pass
        return rev_map
