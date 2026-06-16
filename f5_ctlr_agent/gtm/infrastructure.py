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
GTM infrastructure management for servers and virtual servers.

This module handles the lifecycle of GSLB servers and virtual servers,
including creation, updates, and cleanup.
"""

import logging
from f5_cccl.exceptions import F5CcclError
from f5_ctlr_agent.gtm.utils import GTMUtils

log = logging.getLogger(__name__)


class GTMInfrastructure:
    """Manages GTM infrastructure (servers and virtual servers).
    
    This class handles:
    - GSLB server creation and management
    - Virtual server creation on GSLB servers
    - Datacenter validation
    - Infrastructure orchestration with snapshot-based skipping
    - Cleanup of unused servers and virtual servers
    """
    
    def __init__(self, gtm, partition, local_cluster_name=None, cluster_digital_asset_id=None):
        """Initialize GTM Infrastructure manager.

        Args:
            gtm: BIG-IP GTM object from management root
            partition (str): Partition to manage
            local_cluster_name (str, optional): Cluster identifier
            cluster_digital_asset_id (str, optional): Cluster digital asset ID for server naming
        """
        self._gtm = gtm
        self._partition = partition
        self._local_cluster_name = local_cluster_name
        self._cluster_digital_asset_id = cluster_digital_asset_id
        # enableDataServerMonitor — when False, skip health monitor on GSLB server creation
        self._enable_data_server_monitor = True
    
    def create_gslb_server(self, server_name, datacenter_name, addresses,
                          product='generic-host', virtual_server_discovery='disabled',
                          description=None, monitor=None):
        """Create GTM GSLB server.
        
        Args:
            server_name (str): Name of the GSLB server
            datacenter_name (str): Datacenter to place server in
            addresses (list): List of IP addresses or address dicts
            product (str): Server product type (default: 'generic-host')
            virtual_server_discovery (str): VS discovery mode (default: 'disabled')
            description (str, optional): Server description
            monitor (str, optional): Health monitor path
            
        Returns:
            Server object from BIG-IP
            
        Note:
            Uses idempotent create - returns existing server if already present.
        """
        try:
            server_exists = self._gtm.servers.server.exists(name=server_name)

            if server_exists:
                log.info("GTM: GSLB Server {} already exists".format(server_name))
                server = self._gtm.servers.server.load(name=server_name)
            else:
                log.info("GTM: Creating GSLB server {}".format(server_name))

                create_params = {
                    'name': server_name,
                    'datacenter': datacenter_name,
                    'product': product,
                    'virtualServerDiscovery': virtual_server_discovery
                }

                if addresses:
                    if isinstance(addresses[0], dict):
                        create_params['addresses'] = addresses
                    else:
                        create_params['addresses'] = [{'name': addr} for addr in addresses]

                if description:
                    create_params['description'] = description
                if monitor:
                    create_params['monitor'] = monitor

                server = self._gtm.servers.server.create(**create_params)
                log.info("GTM: GSLB Server {} created successfully".format(server_name))

            return server

        except Exception as e:
            log.error("GTM: Error creating GSLB server {}: {}".format(server_name, str(e)))
            raise F5CcclError(msg="Error creating GSLB server: {}".format(str(e)))
    
    def create_virtual_server_on_gslb_server(self, server_name, vs_name,
                                            destination, enabled=True,
                                            translation_address=None,
                                            translation_port=None, monitor=None,
                                            server_obj=None):
        """Create a virtual server on an existing GSLB server.
        
        Args:
            server_name (str): Name of the GSLB server
            vs_name (str): Name for the virtual server
            destination (str): Destination IP:PORT
            enabled (bool): Whether VS is enabled (default: True)
            translation_address (str, optional): Translation address
            translation_port (int, optional): Translation port
            monitor (str, optional): Health monitor path
            server_obj: Pre-loaded server object (optimization)
            
        Returns:
            Virtual server object from BIG-IP
            
        Note:
            PERF OPTIMIZATION: Accepts pre-loaded server_obj to avoid
            redundant server.load() calls in batch scenarios.
        """
        try:
            # PERF FIX #1: Use pre-loaded server object if available
            if server_obj is None:
                server_obj = self._gtm.servers.server.load(name=server_name)

            create_params = {
                'name': vs_name,
                'destination': destination,
                'enabled': enabled
            }

            if translation_address:
                create_params['translationAddress'] = translation_address
            if translation_port:
                create_params['translationPort'] = translation_port
            if monitor:
                create_params['monitor'] = monitor

            # PERF FIX #2: Use try/create instead of exists+load
            try:
                virtual_server = server_obj.virtual_servers_s.virtual_server.create(**create_params)
                log.info("GTM: Creating virtual server {} on server {}".format(
                    vs_name, server_name))
            except Exception as e:
                if "already exists" in str(e).lower():
                    log.debug("GTM: Virtual server {} already exists on server {}".format(
                        vs_name, server_name))
                    virtual_server = server_obj.virtual_servers_s.virtual_server.load(name=vs_name)
                else:
                    log.error("GTM: Failed to create virtual server {} on server {}: {}".format(
                        vs_name, server_name, str(e)))
                    raise

            return virtual_server

        except Exception as e:
            log.error("GTM: Error creating virtual server {} on server {}: {}".format(
                vs_name, server_name, str(e)))
            raise F5CcclError(msg="Error creating virtual server: {}".format(str(e)))
    
    def ensure_datacenter_exists(self, datacenter_name, location=None, contact=None):
        """Validate that GTM datacenter exists.
        
        Args:
            datacenter_name (str): Name of the datacenter
            location (str, optional): Datacenter location
            contact (str, optional): Contact information
            
        Returns:
            Datacenter object from BIG-IP
            
        Raises:
            F5CcclError: If datacenter doesn't exist
            
        Note:
            Datacenters must be created manually beforehand. This method
            only validates existence, it does not create datacenters.
        """
        try:
            dc_exists = self._gtm.datacenters.datacenter.exists(name=datacenter_name)

            if dc_exists:
                log.info("GTM: [INFRA] Datacenter {} validated".format(datacenter_name))
                datacenter = self._gtm.datacenters.datacenter.load(name=datacenter_name)
            else:
                error_msg = "GTM: Datacenter '{}' does not exist. Please create it manually before deploying GTM configuration.".format(datacenter_name)
                log.error(error_msg)
                raise F5CcclError(msg=error_msg)

            return datacenter

        except F5CcclError:
            raise
        except Exception as e:
            log.error("GTM: Error checking datacenter {}: {}".format(
                datacenter_name, str(e)))
            raise F5CcclError(msg="Error validating datacenter: {}".format(str(e)))
    
    def orchestrate_with_snapshot(self, gtmConfig, parsed, snapshot):
        """Orchestrate infrastructure using snapshot to skip existing resources.
        
        Uses sequential execution. BIG-IP REST API serializes requests internally,
        so parallel execution provides minimal benefit (~30% improvement) at high
        complexity cost.
        
        This method creates servers and virtual servers. It uses a snapshot of
        existing BIG-IP state to skip resources that already exist, significantly
        reducing deployment time.
        
        Args:
            gtmConfig (dict): Full GTM configuration
            parsed (dict): Pre-parsed config data from GTMUtils.parse_gtm_config_once()
            snapshot (dict): BIG-IP state snapshot
            
        Returns:
            dict: Summary of orchestration results with keys:
                  - datacenter: Datacenter name
                  - servers: Number of servers managed
                  - virtual_servers: Number of VSs created/managed
        """
        try:
            datacenter_name = gtmConfig[self._partition].get("dataCenter", None)
            if not datacenter_name:
                raise F5CcclError(msg="GTM: dataCenter not specified for partition {}".format(self._partition))
            if "/" in datacenter_name:
                datacenter_name = datacenter_name.split("/")[-1]

            self.ensure_datacenter_exists(datacenter_name)

            dataservers = parsed['dataservers']
            vs_inventory = parsed['vs_inventory']

            if not dataservers:
                return {"datacenter": datacenter_name, "servers": 0, "virtual_servers": 0}

            log.info("GTM: DataServers to process: {}".format(sorted(dataservers)))

            # Create only MISSING servers (use snapshot for existence check)
            log.info("GTM: [INFRA] Checking {} dataservers against snapshot...".format(len(dataservers)))
            created_server_objects = {}
            servers_created = 0
            servers_skipped = 0

            for dataserver_ip in sorted(dataservers):
                pool_namespace = parsed.get('dataserver_namespaces', {}).get(dataserver_ip, '')
                server_name = GTMUtils.format_server_name(
                    dataserver_ip, self._local_cluster_name,
                    self._cluster_digital_asset_id, pool_namespace)

                if server_name in snapshot['servers']:
                    # Server exists — load object for VS creation
                    log.debug("GTM: Server {} exists (from snapshot)".format(server_name))
                    created_server_objects[server_name] = self._gtm.servers.server.load(name=server_name)
                    servers_skipped += 1
                else:
                    # Server doesn't exist — create it
                    server = self.create_gslb_server(
                        server_name=server_name,
                        datacenter_name=datacenter_name,
                        addresses=[dataserver_ip],
                        product='bigip',
                        virtual_server_discovery='disabled',
                        monitor='/Common/gateway_icmp' if self._enable_data_server_monitor else None)
                    created_server_objects[server_name] = server
                    servers_created += 1

            log.info("GTM: [SNAPSHOT] Servers: {} created, {} skipped (already exist)".format(
                servers_created, servers_skipped))

            # Create only MISSING VSs — lazy load VS names per server
            log.info("GTM: [INFRA] Creating missing virtual servers across {} servers...".format(
                len(vs_inventory)))
            total_vs_created = 0
            total_vs_skipped = 0

            for server_name, vs_set in vs_inventory.items():
                if server_name not in created_server_objects:
                    continue

                server_obj = created_server_objects[server_name]

                # Lazy VS load: only fetch when we actually need to check
                existing_vs = snapshot['server_vs'].get(server_name, set())
                if not existing_vs:
                    try:
                        existing_vs = {vs.name for vs in server_obj.virtual_servers_s.get_collection()}
                        snapshot['server_vs'][server_name] = existing_vs
                        log.info("GTM: [SNAPSHOT] Lazy-loaded {} VSs for server {}".format(
                            len(existing_vs), server_name))
                    except Exception as e:
                        # CRITICAL: Distinguish transient vs permanent errors
                        # - Transient error on server with 50 VSs → raising is CHEAPER than 100 create calls
                        # - Permanent error (new server, no VSs) → empty set is correct
                        if GTMUtils.is_transient_error(e):
                            log.warning("GTM: [SNAPSHOT] Transient error fetching VSs for server {}, "
                                       "raising to avoid issue in subsequent operations: {}".format(
                                server_name, str(e)))
                            raise F5CcclError(
                                msg="VS fetch failed for {}: {}".format(server_name, str(e)))
                        else:
                            log.debug("GTM: [SNAPSHOT] No existing VSs for server {} (permanent error): {}".format(
                                server_name, str(e)))
                            existing_vs = set()

                for member_ip, vs_name, destination in vs_set:
                    if vs_name in existing_vs:
                        total_vs_skipped += 1
                        continue
                    try:
                        self.create_virtual_server_on_gslb_server(
                            server_name=server_name,
                            vs_name=vs_name,
                            destination=destination,
                            enabled=True,
                            server_obj=server_obj)
                        total_vs_created += 1
                        
                        # Progress log every 100 VSs created
                        if total_vs_created % 100 == 0:
                            total_processed = total_vs_created + total_vs_skipped
                            log.info("GTM: [INFRA] VS progress: {} created, {} skipped ({} total processed)".format(
                                total_vs_created, total_vs_skipped, total_processed))
                    except F5CcclError as e:
                        # Log error but continue
                        log.error("GTM: Error creating VS {} on server {}: {}".format(
                            vs_name, server_name, str(e)))
                        continue

            log.info("GTM: [SNAPSHOT] VSs: {} created, {} skipped".format(
                total_vs_created, total_vs_skipped))

            return {
                "datacenter": datacenter_name,
                "servers": len(created_server_objects),
                "virtual_servers": total_vs_created + total_vs_skipped
            }

        except Exception as e:
            log.error("GTM: Critical error during infrastructure orchestration: {}".format(str(e)))
            raise F5CcclError(msg="Infrastructure orchestration failed: {}".format(str(e)))
    
    # ========================================================================
    # CLEANUP METHODS
    # ========================================================================
    
    def cleanup_infrastructure_from_bigip(self, expected_members):
        """Clean up VSs and servers by comparing BIG-IP state with expected config.
        
        Single-pass cleanup that removes orphaned virtual servers and servers
        with no remaining virtual servers.
        
        Args:
            expected_members (dict): Expected pool members {pool_name: set(member_refs)}
            
        Note:
            This is called during initial sync/restart to clean up resources
            that are no longer in the configuration.
        """
        try:
            all_expected_members = set()
            all_expected_servers = set()
            for pool_name, member_set in expected_members.items():
                all_expected_members.update(member_set)
                for member_ref in member_set:
                    server_name = member_ref.split(':')[0]
                    all_expected_servers.add(server_name)

            log.debug("GTM: Expected members after create: {}".format(all_expected_members))
            log.debug("GTM: Expected servers after create: {}".format(all_expected_servers))

            for server_name in all_expected_servers:
                try:
                    if not self._gtm.servers.server.exists(name=server_name):
                        continue

                    server = self._gtm.servers.server.load(name=server_name)

                    vs_list = list(server.virtual_servers_s.get_collection())

                    remaining_vs = []
                    for vs in vs_list:
                        member_ref = "{}:{}".format(server_name, vs.name)
                        if member_ref not in all_expected_members:
                            log.info("GTM: Deleting orphaned VS {} from server {} (restart cleanup)".format(
                                vs.name, server_name))
                            vs.delete()
                        else:
                            remaining_vs.append(vs)

                    if len(remaining_vs) == 0:
                        log.info("GTM: Deleting server {} with no VSs (restart cleanup)".format(
                            server_name))
                        server.delete()

                except Exception as e:
                    log.error("GTM: Error processing server {} during restart cleanup: {}".format(
                        server_name, str(e)))
                    raise F5CcclError(msg="Restart cleanup failed for server {}: {}".format(
                        server_name, str(e)))

        except Exception as e:
            log.error("GTM: Error during infrastructure cleanup from BIG-IP: {}".format(str(e)))
            raise F5CcclError(msg="Infrastructure cleanup from BIG-IP failed: {}".format(str(e)))
