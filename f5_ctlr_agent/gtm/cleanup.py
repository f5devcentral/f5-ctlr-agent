"""GTM Resource Cleanup Module.

This module handles cleanup of orphaned GTM resources including virtual servers,
GSLB servers, and pool members. Supports optimized batch operations and
distinguishes between transient and permanent errors for retry logic.
"""

import logging
from f5_cccl.exceptions import F5CcclError
from f5_ctlr_agent.gtm.utils import GTMUtils

log = logging.getLogger(__name__)


class GTMCleanup:
    """Manages cleanup of orphaned GTM resources.
    
    This class provides methods for cleaning up virtual servers, GSLB servers,
    and pool members that are no longer referenced in the configuration. It uses
    optimized batch operations to minimize API calls and includes robust error
    handling with transient/permanent error distinction.
    
    Attributes:
        gtm: F5 SDK GTM object
        partition: BIG-IP partition name
        pool_manager: GTMPool instance for member removal
    """

    def __init__(self, gtm, partition, pool_manager=None, local_cluster_name=None,
                 digital_asset_id=None, namespace=None):
        """Initialize GTM cleanup manager.
        
        Args:
            gtm: F5 SDK GTM object for API operations
            partition: BIG-IP partition name
            pool_manager: Optional GTMPool instance for member operations
            local_cluster_name (str, optional): Cluster identifier
            digital_asset_id (str, optional): Cluster digital asset ID for server naming
            namespace (str, optional): Default namespace for resource identification
        """
        self.gtm = gtm
        self.partition = partition
        self._pool_manager = pool_manager
        self._local_cluster_name = local_cluster_name
        self._digital_asset_id = digital_asset_id
        self._namespace = namespace

    def cleanup_orphaned_members_with_snapshot(self, expected_members, snapshot):
        """Remove orphaned pool members using snapshot data.
        
        Args:
            expected_members: Dict mapping pool_name -> set of expected member names
            snapshot: BIG-IP state snapshot from GTMSnapshot
        
        Raises:
            F5CcclError: If cleanup fails for any pool
        """
        orphan_count = 0
        cleanup_failures = 0
        for pool_name, expected_member_set in expected_members.items():
            actual_members = snapshot['pool_members'].get(pool_name, set())
            members_to_delete = actual_members - expected_member_set

            if not members_to_delete:
                continue

            log.info("GTM: [SNAPSHOT] Removing {} orphaned members from pool {}".format(
                len(members_to_delete), pool_name))

            try:
                pool_obj = self.gtm.pools.a_s.a.load(name=pool_name, partition=self.partition)
                for member_name in members_to_delete:
                    if self._pool_manager:
                        self._pool_manager.remove_member(
                            pool_name, member_name, pool_obj=pool_obj)
                    else:
                        # Fallback if pool manager not available
                        if pool_obj.members_s.member.exists(name=member_name, partition="Common"):
                            memObj = pool_obj.members_s.member.load(name=member_name, partition="Common")
                            memObj.delete()
                            log.info("GTM: Removed orphaned member {} from pool {}".format(
                                member_name, pool_name))
                    orphan_count += 1
            except Exception as e:
                log.error("GTM: [SNAPSHOT] Error cleaning up orphans in pool {}: {}".format(
                    pool_name, str(e)))
                cleanup_failures += 1

        if cleanup_failures > 0:
            raise F5CcclError(
                msg="GTM: Orphan cleanup incomplete — {} pool(s) failed".format(
                    cleanup_failures))

        if orphan_count > 0:
            log.info("GTM: [SNAPSHOT] Removed {} total orphaned members".format(orphan_count))
        else:
            log.debug("GTM: [SNAPSHOT] No orphaned members found")

    def cleanup_unused_virtual_servers(self, oldConfig, newConfig, 
                                       old_parsed=None, new_parsed=None):
        """Clean up virtual servers that are no longer referenced.
        
        Args:
            oldConfig: Previous GTM configuration dict
            newConfig: Current GTM configuration dict
            old_parsed: Optional pre-parsed old config data
            new_parsed: Optional pre-parsed new config data
        
        Raises:
            F5CcclError: On transient cleanup errors (permanent errors logged only)
        """
        vs_cleanup_errors = []
        try:
            log.debug("GTM: Starting cleanup of unused virtual servers")

            if old_parsed is not None:
                old_members = old_parsed['all_member_refs']
            else:
                old_parsed_data = GTMUtils.parse_gtm_config_once(
                    oldConfig,
                    self.partition,
                    local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._digital_asset_id,
                    namespace=self._namespace)
                old_members = old_parsed_data['all_member_refs']

            if new_parsed is not None:
                new_members = new_parsed['all_member_refs']
            else:
                new_parsed_data = GTMUtils.parse_gtm_config_once(
                    newConfig,
                    self.partition,
                    local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._digital_asset_id,
                    namespace=self._namespace)
                new_members = new_parsed_data['all_member_refs']

            members_to_delete = old_members - new_members

            if not members_to_delete:
                log.debug("GTM: No unused virtual servers to clean up")
                return

            log.debug("GTM: Members to delete: {}".format(members_to_delete))

            # Group deletions by server name
            deletions_by_server = {}
            for member_ref in members_to_delete:
                parts = member_ref.split(':')
                if len(parts) != 2:
                    continue
                server_name, vs_name = parts[0], parts[1]
                if server_name not in deletions_by_server:
                    deletions_by_server[server_name] = set()
                deletions_by_server[server_name].add(vs_name)

            # Batch-process each server ONCE
            for server_name, vs_names_to_delete in deletions_by_server.items():
                try:
                    if not self.gtm.servers.server.exists(name=server_name):
                        log.debug("GTM: Server {} does not exist, skipping".format(server_name))
                        continue

                    server = self.gtm.servers.server.load(name=server_name)

                    all_vs = server.virtual_servers_s.get_collection()

                    vs_by_name = {vs.name: vs for vs in all_vs}

                    deleted_count = 0
                    for vs_name in vs_names_to_delete:
                        if vs_name in vs_by_name:
                            log.info("GTM: Deleting unused virtual server {} from server {}".format(
                                vs_name, server_name))
                            vs_by_name[vs_name].delete()
                            deleted_count += 1
                        else:
                            log.debug("GTM: VS {} not found on server {}, already gone".format(
                                vs_name, server_name))

                    if deleted_count > 0:
                        log.info("GTM: Deleted {} unused virtual server(s) from server {}".format(
                            deleted_count, server_name))

                except Exception as e:
                    log.error("GTM: Error processing server {} for VS cleanup: {}".format(
                        server_name, str(e)))
                    vs_cleanup_errors.append((server_name, e))

            log.debug("GTM: Completed cleanup of unused virtual servers")

        except Exception as e:
            log.error("GTM: Error during virtual server cleanup: {}".format(str(e)))
            vs_cleanup_errors.append(("ALL", e))
        
        # After all servers processed, only raise if TRANSIENT errors occurred
        transient_errors = []
        for server_name, error in vs_cleanup_errors:
            if GTMUtils.is_transient_error(error):
                transient_errors.append((server_name, str(error)))
            else:
                log.warning("GTM: Permanent error during VS cleanup for {} (not retrying): {}".format(
                    server_name, str(error)))
        
        if transient_errors:
            error_summary = "; ".join(["{}: {}".format(srv, err) for srv, err in transient_errors])
            raise F5CcclError(msg="VS cleanup failed with transient errors for {} server(s): {}".format(
                len(transient_errors), error_summary))
        
        log.info("GTM: ✓ Virtual server cleanup completed successfully")

    def cleanup_unused_gslb_servers(self, datacenter_name=None, oldConfig=None, newConfig=None,
                                    old_parsed=None, new_parsed=None):
        """Clean up GSLB servers that have no virtual servers.
        
        Args:
            datacenter_name: Optional datacenter filter
            oldConfig: Previous GTM configuration dict
            newConfig: Current GTM configuration dict
            old_parsed: Optional pre-parsed old config data
            new_parsed: Optional pre-parsed new config data
        
        Raises:
            F5CcclError: On transient cleanup errors (permanent errors logged only)
        """
        try:
            log.debug("GTM: Starting cleanup of unused GSLB servers")

            if old_parsed is not None:
                old_servers = old_parsed['all_server_names']
            else:
                old_parsed_data = GTMUtils.parse_gtm_config_once(
                    oldConfig,
                    list(oldConfig.keys())[0] if oldConfig else self.partition,
                    local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._digital_asset_id,
                    namespace=self._namespace)
                old_servers = old_parsed_data['all_server_names']

            if new_parsed is not None:
                new_servers = new_parsed['all_server_names']
            else:
                new_parsed_data = GTMUtils.parse_gtm_config_once(
                    newConfig,
                    list(newConfig.keys())[0] if newConfig else self.partition,
                    local_cluster_name=self._local_cluster_name,
                    digital_asset_id=self._digital_asset_id,
                    namespace=self._namespace)
                new_servers = new_parsed_data['all_server_names']

            # Check ALL old servers (may have 0 VSs after VS cleanup)
            servers_to_check = old_servers.copy()

            if not servers_to_check:
                log.debug("GTM: No GSLB servers to check for cleanup")
                return

            log.debug("GTM: Servers to check for cleanup: {}".format(servers_to_check))

            # Batch-fetch ALL servers in ONE API call
            all_bigip_servers = self.gtm.servers.get_collection()

            servers_by_name = {s.name: s for s in all_bigip_servers}

            if datacenter_name:
                servers_by_name = {
                    name: srv for name, srv in servers_by_name.items()
                    if getattr(srv, 'datacenter', '').split('/')[-1] == datacenter_name
                }

            deleted_count = 0
            server_cleanup_errors = []
            for server_name in servers_to_check:
                if server_name not in servers_by_name:
                    log.debug("GTM: Server {} not found on BIG-IP, skipping".format(server_name))
                    continue

                server = servers_by_name[server_name]

                try:
                    vs_list = list(server.virtual_servers_s.get_collection())
                    vs_count = len(vs_list)

                    if vs_count == 0:
                        if server_name not in new_servers:
                            # Server removed from config entirely
                            log.info("GTM: Deleting unused GSLB server {} (removed from config)".format(
                                server_name))
                            server.delete()
                            deleted_count += 1
                        else:
                            # Still in config but has no VSs left
                            log.info("GTM: Deleting GSLB server {} (no virtual servers remaining)".format(
                                server_name))
                            server.delete()
                            deleted_count += 1
                    else:
                        log.debug("GTM: Server {} has {} VSs, keeping it".format(
                            server_name, vs_count))

                except Exception as e:
                    log.error("GTM: Error checking/deleting server {}: {}".format(
                        server_name, str(e)))
                    server_cleanup_errors.append((server_name, e))

            if deleted_count > 0:
                log.info("GTM: Deleted {} unused GSLB server(s)".format(deleted_count))
            
            # After all servers processed, only raise if TRANSIENT errors occurred
            transient_errors = []
            for server_name, error in server_cleanup_errors:
                if GTMUtils.is_transient_error(error):
                    transient_errors.append((server_name, str(error)))
                else:
                    log.warning("GTM: Permanent error during server cleanup for {} (not retrying): {}".format(
                        server_name, str(error)))
            
            if transient_errors:
                error_summary = "; ".join(["{}: {}".format(srv, err) for srv, err in transient_errors])
                raise F5CcclError(msg="GSLB server cleanup failed with transient errors for {} server(s): {}".format(
                    len(transient_errors), error_summary))
            
            log.info("GTM: ✓ GSLB server cleanup completed successfully ✓")

        except F5CcclError:
            raise
        except Exception as e:
            if GTMUtils.is_transient_error(e):
                log.error("GTM: Transient error during GSLB server cleanup: {}".format(str(e)))
                raise F5CcclError(msg="GSLB server cleanup failed: {}".format(str(e)))
            else:
                log.warning("GTM: Permanent error during GSLB server cleanup (not retrying): {}".format(str(e)))

    def retry_pending_cleanup(self, pending_cleanup_state):
        """Retry cleanup operations that failed in a previous operation.
        
        Args:
            pending_cleanup_state: Dict with cleanup context:
                - partition: Partition name
                - oldConfig: Previous configuration
                - target_config: Target configuration
                - old_parsed: Parsed old config
                - new_parsed: Parsed new config
                - datacenter_name: Datacenter filter
        
        Returns:
            bool: True if retry successful, False otherwise
        
        Raises:
            F5CcclError: On retry failure
        """
        if pending_cleanup_state is None:
            log.debug("GTM: No pending cleanup to retry")
            return True
        
        log.info("GTM: Retrying pending cleanup operations")
        oldConfig = pending_cleanup_state['oldConfig']
        target_config = pending_cleanup_state['target_config']
        old_parsed = pending_cleanup_state['old_parsed']
        new_parsed = pending_cleanup_state['new_parsed']
        datacenter_name = pending_cleanup_state['datacenter_name']
        
        vs_cleanup_error = None
        server_cleanup_error = None
        
        # Retry VS cleanup
        try:
            log.info("GTM: Retrying VS cleanup")
            self.cleanup_unused_virtual_servers(oldConfig, target_config,
                                               old_parsed=old_parsed, new_parsed=new_parsed)
        except Exception as e:
            log.error("GTM: VS cleanup retry failed, will still attempt server cleanup: %s", e)
            vs_cleanup_error = e
        
        # Retry GSLB server cleanup
        try:
            log.info("GTM: Retrying GSLB server cleanup")
            self.cleanup_unused_gslb_servers(datacenter_name, oldConfig, target_config,
                                            old_parsed=old_parsed, new_parsed=new_parsed)
        except Exception as e:
            log.error("GTM: GSLB server cleanup retry failed: %s", e)
            server_cleanup_error = e
        
        # Check results
        if not vs_cleanup_error and not server_cleanup_error:
            log.info("GTM: ✓✓✓ Pending cleanup retry completed successfully ✓✓✓")
            return True
        
        # If still failing, re-raise
        if vs_cleanup_error:
            raise F5CcclError(msg="VS cleanup retry failed: {}".format(str(vs_cleanup_error)))
        if server_cleanup_error:
            raise F5CcclError(msg="GSLB server cleanup retry failed: {}".format(str(server_cleanup_error)))
