"""GTM Pool Management Module.

This module handles GTM pool creation, updates, member management, and deletion.
Supports both legacy and current member formats with backward compatibility.
"""

import logging
from f5_cccl.exceptions import F5CcclError
from f5_ctlr_agent.gtm.utils import GTMUtils

log = logging.getLogger(__name__)


class GTMPool:
    """Manages GTM pool lifecycle and member operations.
    
    This class provides methods for creating, updating, and deleting GTM pools,
    as well as managing pool members. It includes performance optimizations such
    as batched attribute updates and optional validation skipping for orchestrated
    infrastructure.
    
    Attributes:
        gtm: F5 SDK GTM object
        partition: BIG-IP partition name
        active_tenants: List of active tenants for ownership validation
        deleted_tenants: List of deleted tenants for ownership validation
    """

    def __init__(self, gtm, partition, active_tenants=None, deleted_tenants=None,
                 local_cluster_name=None, cluster_digital_asset_id=None):
        """Initialize GTM pool manager.

        Args:
            gtm: F5 SDK GTM object for API operations
            partition: BIG-IP partition name
            active_tenants: Optional list of active tenants for member validation
            deleted_tenants: Optional list of deleted tenants for member validation
            local_cluster_name (str, optional): Cluster identifier
            cluster_digital_asset_id (str, optional): Cluster digital asset ID for server naming
        """
        self.gtm = gtm
        self.partition = partition
        self._active_tenants = active_tenants or []
        self._deleted_tenants = deleted_tenants or []
        self._local_cluster_name = local_cluster_name
        self._cluster_digital_asset_id = cluster_digital_asset_id

    def create_pool(self, config, monitors, skip_member_validation=False):
        """Create or update GTM pools from configuration.
        
        Args:
            config: Pool configuration dict with 'pools' list
            monitors: Monitor string (e.g., "/Common/http and /Common/tcp")
            skip_member_validation: If True, bypass existence checks for members
                                   (used when infrastructure is pre-orchestrated)
        
        Raises:
            F5CcclError: On pool creation or update failure
        """
        try:
            for pool in config['pools']:
                pool_name = GTMUtils.apply_cluster_prefix(
                    pool['name'], self._local_cluster_name)

                # Enhancement 5: pool-monitor.disabled — skip monitor attachment when disabled
                pool_monitor_cfg = pool.get('pool-monitor') or {}
                pool_monitor_disabled = pool_monitor_cfg.get('disabled', False)

                # Enhancement 3: fallback IP — support camelCase (new spec) and kebab-case (legacy)
                fallback_ip = pool.get('fallbackIp') or pool.get('fallback-ip', '')

                # Enhancement 4: namespace for new server naming format
                pool_namespace = pool.get('namespace', '')

                exist = self.gtm.pools.a_s.a.exists(name=pool_name, partition=self.partition)
                if not exist:
                    log.info('GTM: Creating Pool: {}'.format(pool_name))
                    pool_create_kwargs = {
                        'name': pool_name,
                        'partition': self.partition,
                        'fallbackMode': pool['fallbackMode'],
                        'loadBalancingMode': pool['LoadBalancingMode'],
                    }
                    if fallback_ip and pool.get('fallbackMode') == 'fallback-ip':
                        pool_create_kwargs['fallbackIpv4'] = fallback_ip
                    pl = self.gtm.pools.a_s.a.create(**pool_create_kwargs)
                else:
                    pl = self.gtm.pools.a_s.a.load(
                        name=pool_name,
                        partition=self.partition)

                # PERF FIX #4: Batch attribute updates into a single .update() call
                needs_update = False
                if not pool_monitor_disabled and monitors != "":
                    pl.monitor = monitors
                    needs_update = True
                if pl.fallbackMode != pool['fallbackMode']:
                    pl.fallbackMode = pool['fallbackMode']
                    needs_update = True
                if fallback_ip and pool.get('fallbackMode') == 'fallback-ip':
                    if getattr(pl, 'fallbackIpv4', '') != fallback_ip:
                        pl.fallbackIpv4 = fallback_ip
                        needs_update = True
                if pl.loadBalancingMode != pool['LoadBalancingMode']:
                    pl.loadBalancingMode = pool['LoadBalancingMode']
                    needs_update = True
                if needs_update:
                    pl.update()
                    log.debug('GTM: Updated pool {} attributes'.format(pool_name))

                if bool(pool['members']):
                    pool_dataserver = pool.get('DataServer', '')

                    for member_spec in pool['members']:
                        if '|' in member_spec:
                            separator = '|'
                        else:
                            separator = ':'

                        parts = member_spec.split(separator)

                        if len(parts) == 3:
                            dataserver = parts[0]
                            member_ip = parts[1]
                            member_port = parts[2]
                            destination = "{}:{}".format(member_ip, member_port)
                        elif len(parts) == 2:
                            if not pool_dataserver:
                                log.warning("GTM: Member '{}' in pool {} has no DataServer. Skipping.".format(
                                    member_spec, pool['name']))
                                continue
                            dataserver = pool_dataserver
                            member_ip = parts[0]
                            member_port = parts[1]
                            destination = "{}:{}".format(member_ip, member_port)
                        else:
                            log.warning("GTM: Unrecognized member format '{}' in pool {}. Using as-is.".format(
                                member_spec, pool['name']))
                            self.add_member(
                                pl, pool_name, member_spec,
                                skip_validation=skip_member_validation)
                            continue

                        vs_name = GTMUtils.format_vs_name(
                            destination, self._local_cluster_name)
                        server_name = GTMUtils.format_server_name(
                            dataserver, self._local_cluster_name,
                            self._cluster_digital_asset_id, pool_namespace)
                        member_name = "{}:{}".format(server_name, vs_name)

                        # PERF FIX #3: Skip validation when infrastructure is already orchestrated
                        self.add_member(
                            pl, pool_name, member_name,
                            skip_validation=skip_member_validation)
        except F5CcclError as e:
            log.error("GTM: Error while creating pool: %s", e)
            raise e

    def add_member(self, pool, pool_name, member_name, skip_validation=False):
        """Add member to GTM pool with optional validation.
        
        Args:
            pool: Pre-loaded pool object (or None to load dynamically)
            pool_name: Name of the pool
            member_name: Member reference (format: "server_name:vs_name")
            skip_validation: If True, bypass server/VS existence checks
                            (used when infrastructure is pre-orchestrated)
        
        Raises:
            F5CcclError: On member addition failure or missing infrastructure
        """
        try:
            if not bool(pool):
                pool = self.gtm.pools.a_s.a.load(name=pool_name, partition=self.partition)

            # PERF FIX #3: Fast path - infrastructure already guaranteed by orchestrate
            if skip_validation:
                try:
                    pool.members_s.member.create(name=member_name, partition="Common")
                    log.info('GTM: Added member {} to pool {}'.format(member_name, pool_name))
                except Exception as e:
                    if "already exists" in str(e).lower():
                        log.debug('GTM: Member {} already in pool {}'.format(member_name, pool_name))
                    else:
                        raise F5CcclError(msg="Error adding member: {}".format(str(e)))
                return

            # Original validation path (backward compatibility)
            exist = pool.members_s.member.exists(name=member_name)
            if not exist:
                s = member_name.split(":")
                server = s[0].split("/")[-1]
                vs_name = s[1]
                serverExist = self.gtm.servers.server.exists(name=server)
                if serverExist:
                    sl = self.gtm.servers.server.load(name=server)
                    vsExist = sl.virtual_servers_s.virtual_server.exists(name=vs_name)
                    if vsExist:
                        pmExist = pool.members_s.member.exists(
                            name=member_name,
                            partition="Common")
                        if not pmExist:
                            pool.members_s.member.create(name=member_name, partition="Common")
                            log.info('GTM: Added member {} to pool {}'.format(member_name, pool_name))
                    else:
                        raise F5CcclError(
                            msg="Virtual Server Resource not Available in BIG-IP")
                else:
                    pool = self.gtm.pools.a_s.a.load(name=pool_name, partition=self.partition)
                    pool.delete()
                    raise F5CcclError(msg="Server Resource not Available in BIG-IP")
        except (F5CcclError) as e:
            log.debug("GTM: Error while adding member to pool.")
            raise e

    def remove_member(self, pool_name, member_name, pool_obj=None):
        """Remove member from GTM pool.
        
        Args:
            pool_name: Name of the pool
            member_name: Member reference to remove
            pool_obj: Optional pre-loaded pool object for efficiency
        
        Note:
            Includes tenant ownership validation to prevent removing members
            created by different CIS instances.
        """
        try:
            try:
                parts = member_name.split(":")
                if len(parts) >= 2 and "/" in parts[1]:
                    tenant = parts[1].split("/")[1]
                    if tenant not in self._active_tenants + self._deleted_tenants:
                        log.debug("GTM: Not removing the pool member %s as it may not be created by this CIS instance", member_name)
                        return
                else:
                    log.debug("GTM: Removing member {} (new format, no tenant check)".format(member_name))
            except (IndexError, AttributeError):
                log.debug("GTM: Could not parse tenant from member {}, proceeding with removal".format(member_name))

            # PERF FIX #11: Use pre-loaded pool object if available
            if pool_obj is None:
                exist = self.gtm.pools.a_s.a.exists(name=pool_name, partition=self.partition)
                if not exist:
                    return
                pool_obj = self.gtm.pools.a_s.a.load(name=pool_name, partition=self.partition)

            if pool_obj.members_s.member.exists(name=member_name, partition="Common"):
                memObj = pool_obj.members_s.member.load(name=member_name, partition="Common")
                memObj.delete()
                log.info("GTM: Member {} deleted from pool {}".format(member_name, pool_name))
            else:
                log.debug("GTM: Member {} not found in pool {} (already deleted)".format(member_name, pool_name))
        except Exception as e:
            log.error("GTM: Error while removing pool member {}: {}".format(member_name, str(e)))
            raise e

    def delete_pool(self, wideip_name, pool_name, working_config=None):
        """Delete GTM pool and all its members.
        
        Args:
            wideip_name: Name of parent wideIP
            pool_name: Name of pool to delete
            working_config: Optional working config copy (for retry-safety)
        
        Raises:
            F5CcclError: On transient deletion errors (permanent errors logged only)
        """
        try:
            prefixed_pool_name = GTMUtils.apply_cluster_prefix(
                pool_name, self._local_cluster_name)
            # Use working_config if provided, otherwise fall back to instance config
            # Note: working_config is expected to be provided by caller
            if working_config is None:
                log.warning("GTM: delete_pool called without working_config, operation may not be safe")
                return

            config = working_config
            wideips = config.get(self.partition, {}).get('wideIPs', None)
            if wideips is None:
                return

            for index, wideip in enumerate(wideips):
                if wideip_name == wideip['name']:
                    for pool_index, pool in enumerate(wideip['pools']):
                        if pool['name'] == pool_name and pool['members'] is not None:
                            members_to_remove = list(pool['members'])
                            pool_dataserver = pool.get('DataServer')
                            pool_namespace = pool.get('namespace', '')

                            # PERF FIX #11: Load pool once for all member removals
                            pool_obj = None
                            if self.gtm.pools.a_s.a.exists(name=prefixed_pool_name, partition=self.partition):
                                pool_obj = self.gtm.pools.a_s.a.load(name=prefixed_pool_name, partition=self.partition)

                            for member in members_to_remove:
                                member_ref = GTMUtils.convert_member_to_bigip_reference(
                                    member,
                                    pool_dataserver,
                                    local_cluster_name=self._local_cluster_name,
                                    digital_asset_id=self._cluster_digital_asset_id,
                                    namespace=pool_namespace)
                                self.remove_member(prefixed_pool_name, member_ref, pool_obj=pool_obj)
                            config[self.partition]['wideIPs'][index]["pools"][pool_index]['members'] = None
                            break
                    break

            if self.gtm.pools.a_s.a.exists(name=prefixed_pool_name, partition=self.partition):
                obj = self.gtm.pools.a_s.a.load(name=prefixed_pool_name, partition=self.partition)
                if len(obj.members_s.get_collection()) == 0:
                    # Detach pool from wideIP before deletion
                    # This is critical - BIG-IP won't delete a pool that's still referenced
                    from f5_ctlr_agent.gtm.wideip import GTMWideIP
                    wideip_module = GTMWideIP(
                        self.gtm,
                        self.partition,
                        local_cluster_name=self._local_cluster_name)
                    wideip_module.remove_pool_from_wideip(wideip_name, pool_name)
                    
                    # Now safe to delete pool
                    obj.delete()
                    log.info("GTM: Deleted pool {}".format(prefixed_pool_name))
                    config[self.partition]['wideIPs'][index]["pools"].pop(pool_index)
            else:
                log.info("GTM: Pool {} already deleted".format(prefixed_pool_name))
        except F5CcclError:
            # Re-raise F5CcclError as-is
            raise
        except Exception as e:
            # Check if permanent or transient error
            if GTMUtils.is_transient_error(e):
                log.error("GTM: Transient error deleting pool {}: {}".format(prefixed_pool_name, str(e)))
                raise F5CcclError(msg="Transient error deleting pool {}: {}".format(prefixed_pool_name, str(e)))
            else:
                # Permanent error - log but DON'T raise
                log.debug("GTM: Permanent error deleting pool {} (treating as success): {}".format(prefixed_pool_name, str(e)))

    def remove_unused_members_legacy(self, gtm_config):
        """Remove unused GTM pool members from BIG-IP created by CIS <= v2.7.1.
        
        This is a legacy cleanup method to migrate from old member format
        (pool_name/Shared/vs_name) to new format (server_name:vs_name).
        
        Args:
            gtm_config: GTM configuration dict with wideIPs
        
        Raises:
            F5CcclError: On cleanup failure
        """
        try:
            def _get_value(d, k):
                if d[k] is None:
                    return dict()
                return d[k]

            def _get_virtualNames_from_member(gtm_members):
                list_gtm_virtuals = {}
                for pool_name in gtm_members:
                    list_gtm_virtuals[pool_name] = []
                    for gtm_member in gtm_members[pool_name]:
                        if '/Shared/' in gtm_member:
                            list_gtm_virtuals[pool_name].append(gtm_member.split('/Shared/')[1])
                        else:
                            log.debug("GTM: Skipping new format member in legacy cleanup: {}".format(gtm_member))
                return list_gtm_virtuals

            def _find_deleted_members(gtm_members, bigip_members):
                del_gtm_members = {}
                list_gtm_virtuals = _get_virtualNames_from_member(gtm_members)
                for pool_name in gtm_members:
                    del_gtm_members[pool_name] = []
                    for gtm_member in gtm_members[pool_name]:
                        if "ingress_link_" not in gtm_member and '/Shared/' in gtm_member and pool_name in bigip_members:
                            gtmPoolObj, gtmMemberName = gtm_member.split('/Shared/')
                            parseSearchStrfromMember = ('_').join(gtmMemberName.split('_')[:-1])
                            extra_bigip_members = list(set(bigip_members[pool_name]) - set(list_gtm_virtuals[pool_name]))
                            for bigipPoolMember in extra_bigip_members:
                                if bigipPoolMember.startswith(parseSearchStrfromMember):
                                    member = gtmPoolObj + '/Shared/' + bigipPoolMember
                                    del_gtm_members[pool_name].append(member)
                return del_gtm_members

            gtm_pools = []
            for wip in _get_value(gtm_config, "wideIPs"):
                gtm_pools += wip["pools"]

            gtm_members, bigip_members = {}, {}
            for p in gtm_pools:
                if p.get("members"):
                    gtm_members[p['name']] = p["members"]
                    try:
                        pool_name = GTMUtils.apply_cluster_prefix(
                            p['name'], self._local_cluster_name)
                        exist = self.gtm.pools.a_s.a.exists(name=pool_name, partition=self.partition)
                        if not exist:
                            continue
                        pool = self.gtm.pools.a_s.a.load(name=pool_name, partition=self.partition)
                        bigip_members[p['name']] = [gtmMember.name for gtmMember in pool.members_s.get_collection()]
                    except Exception as e:
                        log.error("GTM: Error fetching pool {} members during legacy cleanup: {}".format(
                            p['name'], str(e)))
                        raise F5CcclError(
                            msg="Legacy cleanup failed for pool {}: {}".format(
                                p['name'], str(e)))

            del_gtm_members = _find_deleted_members(gtm_members, bigip_members)
            try:
                for pool_name in del_gtm_members:
                    for member in del_gtm_members[pool_name]:
                        self.remove_member(pool_name, member)
            except F5CcclError as e:
                log.error("GTM: Error while removing gtm pool member: %s", e)
                raise e
        except F5CcclError as e:
            log.error("GTM: Error while processing for list of pool members to delete: %s", e)
            raise e

    def remove_monitor_from_pool(self, pool_name, monitor_name):
        """Remove monitor from GTM pool.
        
        Args:
            pool_name: Name of the pool
            monitor_name: Name of monitor to remove
        
        Raises:
            F5CcclError: On monitor removal failure
        """
        try:
            prefixed_pool_name = GTMUtils.apply_cluster_prefix(
                pool_name, self._local_cluster_name)
            prefixed_monitor_name = GTMUtils.apply_cluster_prefix(
                monitor_name, self._local_cluster_name)
            # Check pool existence first
            if not self.gtm.pools.a_s.a.exists(name=prefixed_pool_name, partition=self.partition):
                log.info("GTM: Pool {} does not exist, skipping monitor removal".format(prefixed_pool_name))
                return
                
            pool = self.gtm.pools.a_s.a.load(name=prefixed_pool_name, partition=self.partition)
            if hasattr(pool, 'monitor'):
                monitor_ref = f"/{self.partition}/{prefixed_monitor_name}"
                if monitor_ref in pool.monitor:
                    monitors = pool.monitor.split(" and ")
                    monitors.remove(monitor_ref)
                    # Set to "none" if no monitors remain, otherwise rejoin
                    pool.monitor = "none" if len(monitors) == 0 else " and ".join(monitors)
                    pool.update()
                    log.debug("GTM: Detached monitor {} from pool {}".format(prefixed_monitor_name, prefixed_pool_name))
        except F5CcclError as e:
            log.error("Error while removing monitor from pool: %s", e)
            raise e
