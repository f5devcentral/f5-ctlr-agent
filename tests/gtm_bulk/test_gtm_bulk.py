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

"""Unit tests for the GTM bulk path (bulk snapshot and transactional batches).

Run from the repo root: python -m pytest tests/gtm_bulk
"""

import threading
from unittest import mock

import pytest

from f5_ctlr_agent.bigipconfigdriver import GTMManager
from f5_ctlr_agent.gtm.bulk import GTMBulk, DISABLE_ENV

BASE = 'https://bigip/mgmt/'
CLUSTER = 'clu'
UID = 'uid1'
SERVER = 'server_uid1_clu_10_200_0_1'


class _Resp(object):
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class FakeICRS(object):
    """Records iControl REST calls and emulates the transaction endpoints."""

    def __init__(self, items=None, fail_commits=(), fail_get=False):
        self.items = items or {}  # path after 'tm/' -> list of items
        self.fail_commits = set(fail_commits)  # 1-based commit ordinals that fail
        self.fail_get = fail_get
        self._lock = threading.Lock()
        self.gets = []
        self.queued = {}  # tx id -> [(url, body)] in arrival order
        self.committed = []
        self.discarded = []
        self._commit_count = 0

    def get(self, url, params=None, **_):
        if self.fail_get:
            raise RuntimeError('boom')
        path = url.split('/mgmt/tm/', 1)[1]
        self.gets.append((path, params))
        return _Resp({'items': self.items.get(path, [])})

    def post(self, url, json=None, headers=None, **_):
        with self._lock:
            if url.endswith('/tm/transaction'):
                tx_id = str(len(self.queued) + 1)
                self.queued[tx_id] = []
                return _Resp({'transId': tx_id})
            self.queued[headers['X-F5-REST-Coordination-Id']].append((url, json))
        return _Resp({})

    def patch(self, url, json=None, **_):
        tx_id = url.rsplit('/', 1)[1]
        with self._lock:
            self._commit_count += 1
            if self._commit_count in self.fail_commits:
                raise RuntimeError('commit failed')
            assert json == {'state': 'VALIDATING'}
            self.committed.append(self.queued[tx_id])
        return _Resp({})

    def delete(self, url, **_):
        self.discarded.append(url.rsplit('/', 1)[1])
        return _Resp({})


def _root(icrs):
    root = mock.MagicMock()
    root._meta_data = {'uri': BASE, 'hostname': 'bigip'}
    root.icrs = icrs
    return root


def _config(count, monitor_ref='/Common/tcp'):
    wips = []
    for i in range(1, count + 1):
        domain = 'app-{}.example.com'.format(i)
        wips.append({
            'name': domain,
            'LoadBalancingMode': 'round-robin',
            'pools': [{
                'name': domain,
                'LoadBalancingMode': 'round-robin',
                'fallbackMode': 'return-to-dns',
                'order': 0,
                'poolMonitorRef': monitor_ref,
                'members': ['10.200.0.1|10.1.0.{}|80'.format(i)],
            }],
        })
    return {'Common': {'dataCenter': '/Common/dc1', 'wideIPs': wips}}


def _bulk(icrs):
    return GTMBulk(_root(icrs), 'Common', CLUSTER, UID,
                   description_builder=lambda: 'managed-by: ebc | cluster: clu-uid1')


def _empty_snapshot():
    return {'wideips': set(), 'pools': set()}


def test_snapshot_reads_only_wanted_objects_with_three_gets():
    icrs = FakeICRS(items={
        'gtm/server': [{'name': SERVER, 'monitor': '/Common/gateway_icmp'}, {'name': 'other'}],
        'gtm/pool/a': [
            {'name': 'pool-uid1-clu-app-1.example.com', 'partition': 'Common',
             'monitor': '/Common/tcp', 'fallbackMode': 'return-to-dns',
             'membersReference': {'items': [{'name': SERVER + ':vs-clu-10-1-0-1-80'}]}},
            {'name': 'pool-someone-else', 'partition': 'Common'},
        ],
        'gtm/wideip/a': [
            {'name': 'app-1.example.com', 'partition': 'Common', 'aliases': ['a.example.com'],
             'poolLbMode': 'round-robin'},
            {'name': 'unrelated.example.com', 'partition': 'Common'},
        ],
    })
    snap = _bulk(icrs).snapshot_bigip_state(_config(2))

    assert len(icrs.gets) == 3
    assert snap['servers'] == {SERVER, 'other'}
    assert snap['server_monitors'][SERVER] == '/Common/gateway_icmp'
    assert snap['server_monitors']['other'] == ''
    assert snap['pools'] == {'pool-uid1-clu-app-1.example.com'}
    assert snap['pool_members']['pool-uid1-clu-app-1.example.com'] == {SERVER + ':vs-clu-10-1-0-1-80'}
    assert snap['pool_monitors']['pool-uid1-clu-app-1.example.com'] == '/Common/tcp'
    assert snap['wideips'] == {'app-1.example.com'}
    assert snap['wideip_attrs']['app-1.example.com']['aliases'] == ['a.example.com']


def test_virtual_servers_created_in_batches():
    icrs = FakeICRS()
    items = [('ip', 'vs-{}'.format(i), '10.0.0.{}:80'.format(i)) for i in range(600)]

    remaining = _bulk(icrs).create_virtual_servers(SERVER, items)

    assert remaining == []
    assert [len(tx) for tx in icrs.committed] == [250, 250, 100]
    url, body = icrs.committed[0][0]
    assert url == BASE + 'tm/gtm/server/~Common~{}/virtual-servers'.format(SERVER)
    assert set(body) == {'name', 'destination', 'enabled'}


def test_failed_virtual_server_batch_is_returned_and_discarded():
    icrs = FakeICRS(fail_commits={2})
    items = [('ip', 'vs-{}'.format(i), '10.0.0.{}:80'.format(i)) for i in range(600)]

    remaining = _bulk(icrs).create_virtual_servers(SERVER, items)

    assert len(remaining) == 250
    assert len(icrs.committed) == 2
    assert len(icrs.discarded) == 1


def test_wideips_created_with_pool_queued_before_wideip():
    icrs = FakeICRS()
    configs = _config(50)['Common']['wideIPs']

    leftover = _bulk(icrs).create_wideips(configs, _empty_snapshot())

    assert leftover == []
    assert [len(tx) for tx in icrs.committed] == [80, 20]  # 40 + 10 wideIPs, 2 requests each
    flat = [r for tx in icrs.committed for r in tx]
    pool_reqs = [b for u, b in flat if u.endswith('gtm/pool/a')]
    wip_reqs = [b for u, b in flat if u.endswith('gtm/wideip/a')]
    assert len(pool_reqs) == len(wip_reqs) == 50

    for tx in icrs.committed:
        names = [(u.rsplit('/', 1)[1], b['name']) for u, b in tx]
        for kind, name in names:
            if kind == 'a' and name.startswith('app-'):  # a wideIP request
                pool_name = 'pool-uid1-clu-' + name
                assert names.index(('a', pool_name)) < names.index(('a', name))


def test_request_bodies_match_per_object_path():
    icrs = FakeICRS()
    _bulk(icrs).create_wideips(_config(25)['Common']['wideIPs'], _empty_snapshot())

    reqs = {u.rsplit('/', 2)[1]: b for u, b in icrs.committed[0]}
    pool = next(b for u, b in icrs.committed[0] if u.endswith('gtm/pool/a'))
    wideip = next(b for u, b in icrs.committed[0] if u.endswith('gtm/wideip/a'))
    assert reqs  # both kinds present

    assert pool == {
        'name': 'pool-uid1-clu-app-1.example.com', 'partition': 'Common',
        'fallbackMode': 'return-to-dns', 'loadBalancingMode': 'round-robin',
        'monitor': '/Common/tcp',
        'members': [{'name': SERVER + ':vs-clu-10-1-0-1-80', 'partition': 'Common'}],
    }
    assert wideip == {
        'name': 'app-1.example.com', 'partition': 'Common', 'lastResortPool': 'none',
        'poolLbMode': 'round-robin',
        'description': 'managed-by: ebc | cluster: clu-uid1',
        'pools': [{'name': 'pool-uid1-clu-app-1.example.com', 'partition': 'Common',
                   'ratio': 1, 'order': 0}],
    }


def test_existing_and_custom_monitor_wideips_use_per_object_path():
    icrs = FakeICRS()
    configs = _config(30)['Common']['wideIPs']
    configs[0]['pools'][0]['monitors'] = [{'name': 'mon1', 'type': 'http'}]
    snapshot = {'wideips': {configs[1]['name']},
                'pools': {'pool-uid1-clu-' + configs[2]['name']}}

    leftover = _bulk(icrs).create_wideips(configs, snapshot)

    assert leftover == configs[:3]
    assert sum(len(tx) for tx in icrs.committed) == 27 * 2


def test_failed_wideip_batch_is_returned():
    icrs = FakeICRS(fail_commits={1})
    configs = _config(60)['Common']['wideIPs']

    leftover = _bulk(icrs).create_wideips(configs, _empty_snapshot())

    assert leftover == configs[:40]
    assert len(icrs.committed) == 1


def test_small_sets_and_kill_switch_skip_bulk(monkeypatch):
    icrs = FakeICRS()
    bulk = _bulk(icrs)
    few = _config(5)['Common']['wideIPs']
    assert bulk.create_wideips(few, _empty_snapshot()) == few
    assert icrs.queued == {}

    monkeypatch.setenv(DISABLE_ENV, '1')
    assert bulk.enabled(10000) is False
    many = _config(30)['Common']['wideIPs']
    assert bulk.create_wideips(many, _empty_snapshot()) == many
    assert icrs.queued == {}


# -- GTMManager.create_gtm end to end (SDK objects mocked) -------------------
def _manager(icrs):
    root = _root(icrs)
    return GTMManager(root, 'Common', local_cluster_name=CLUSTER, cluster_digital_asset_id=UID)


def test_create_gtm_uses_bulk_path_for_fresh_sync():
    icrs = FakeICRS()
    mgr = _manager(icrs)

    mgr.create_gtm('Common', _config(30))

    gtm = mgr._gtm
    assert [p for p, _ in icrs.gets] == ['gtm/server', 'gtm/pool/a', 'gtm/wideip/a']
    gtm.wideips.a_s.a.create.assert_not_called()
    gtm.pools.a_s.a.create.assert_not_called()
    gtm.pools.a_s.a.load.assert_not_called()
    assert [len(tx) for tx in icrs.committed] == [30, 60]  # virtual servers, then pool+wideIP pairs


def test_create_gtm_falls_back_when_bulk_snapshot_fails():
    icrs = FakeICRS(fail_get=True)
    mgr = _manager(icrs)
    gtm = mgr._gtm
    gtm.pools.a_s.a.load.side_effect = Exception('404 not found')
    gtm.wideips.a_s.a.exists.return_value = False

    mgr.create_gtm('Common', _config(30))

    # Snapshot came from per-object loads; writes still went through transactions.
    gtm.pools.a_s.a.load.assert_called()
    assert [len(tx) for tx in icrs.committed] == [30, 60]


def test_create_gtm_falls_back_per_object_when_batches_fail():
    icrs = FakeICRS(fail_commits=set(range(1, 100)))
    mgr = _manager(icrs)
    gtm = mgr._gtm
    gtm.wideips.a_s.a.exists.return_value = False
    gtm.pools.a_s.a.exists.return_value = False

    mgr.create_gtm('Common', _config(30))

    assert icrs.committed == []
    assert gtm.wideips.a_s.a.create.call_count == 30
    assert gtm.pools.a_s.a.create.call_count == 30


# -- incremental-path optimizations -------------------------------------------
def _cleanup(root=None):
    from f5_ctlr_agent.gtm.cleanup import GTMCleanup
    gtm = mock.MagicMock()
    return GTMCleanup(gtm, 'Common', local_cluster_name=CLUSTER,
                      cluster_digital_asset_id=UID, mgmt_root=root), gtm


def _parsed(members):
    return {'all_member_refs': set(members),
            'all_server_names': {m.split(':')[0] for m in members}}


def test_gslb_server_scan_skipped_when_push_removes_nothing():
    cleanup, gtm = _cleanup()
    old = _parsed(['srvA:vs1'])
    new = _parsed(['srvA:vs1', 'srvA:vs2'])  # pure add

    cleanup.cleanup_unused_gslb_servers('dc1', old_parsed=old, new_parsed=new)

    gtm.servers.get_collection.assert_not_called()


def test_gslb_server_scan_limited_to_servers_that_lost_members():
    cleanup, gtm = _cleanup()
    srv_a = mock.MagicMock()
    srv_a.name = 'srvA'
    srv_a.datacenter = '/Common/dc1'
    srv_a.virtual_servers_s.get_collection.return_value = []
    srv_b = mock.MagicMock()
    srv_b.name = 'srvB'
    srv_b.datacenter = '/Common/dc1'
    gtm.servers.get_collection.return_value = [srv_a, srv_b]
    old = _parsed(['srvA:vs1', 'srvB:vs1'])
    new = _parsed(['srvB:vs1'])

    cleanup.cleanup_unused_gslb_servers('dc1', old_parsed=old, new_parsed=new)

    srv_a.delete.assert_called_once()
    srv_b.virtual_servers_s.get_collection.assert_not_called()


def test_gslb_server_scan_is_full_when_forced_for_retry():
    cleanup, gtm = _cleanup()
    gtm.servers.get_collection.return_value = []
    old = _parsed(['srvA:vs1'])

    cleanup.cleanup_unused_gslb_servers('dc1', old_parsed=old, new_parsed=old, force_scan=True)

    gtm.servers.get_collection.assert_called_once()


def test_unused_virtual_servers_deleted_directly_ignoring_404():
    icrs = mock.MagicMock()
    not_found = Exception('404 Not Found')
    icrs.delete.side_effect = [None, not_found]
    cleanup, gtm = _cleanup(_root(icrs))

    cleanup.cleanup_unused_virtual_servers(
        None, None, old_parsed=_parsed(['srvA:vs1', 'srvA:vs2']), new_parsed=_parsed([]))

    assert [c[0][0] for c in icrs.delete.call_args_list] == [
        BASE + 'tm/gtm/server/~Common~srvA/virtual-servers/vs1',
        BASE + 'tm/gtm/server/~Common~srvA/virtual-servers/vs2']
    gtm.servers.server.load.assert_not_called()


def _orchestrate(vs_count):
    from f5_ctlr_agent.gtm.infrastructure import GTMInfrastructure
    gtm = mock.MagicMock()
    server = gtm.servers.server.load.return_value
    server.monitor = ''
    infra = GTMInfrastructure(gtm, 'Common', CLUSTER, UID)
    vs = {('10.1.0.{}'.format(i), 'vs-{}'.format(i), '10.1.0.{}:80'.format(i))
          for i in range(vs_count)}
    parsed = {'dataservers': {'10.200.0.1'}, 'vs_inventory': {SERVER: vs}}
    snapshot = {'servers': {SERVER}, 'server_vs': {SERVER: set()}}
    infra.orchestrate_with_snapshot(
        {'Common': {'dataCenter': 'dc1'}}, parsed, snapshot)
    return server


def test_orchestrate_posts_without_listing_virtual_servers_for_small_sets():
    server = _orchestrate(5)

    server.virtual_servers_s.get_collection.assert_not_called()
    assert server.virtual_servers_s.virtual_server.create.call_count == 5


def test_orchestrate_lists_virtual_servers_for_large_sets():
    server = _orchestrate(25)

    server.virtual_servers_s.get_collection.assert_called_once()


# -- inline create and fast delete (per-object path) ---------------------------
def _pool_cfg(members=None, monitor='/Common/tcp'):
    return {'pools': [{
        'name': 'app.example.com', 'LoadBalancingMode': 'round-robin',
        'fallbackMode': 'return-to-dns', 'order': 0, 'poolMonitorRef': monitor,
        'DataServer': '10.200.0.1',
        'members': members if members is not None else ['10.1.0.1:80', '10.1.0.2:80']}]}


POOL = 'pool-uid1-clu-app.example.com'
MEMBERS = [SERVER + ':vs-clu-10-1-0-1-80', SERVER + ':vs-clu-10-1-0-2-80']


def _pool_mgr():
    from f5_ctlr_agent.gtm.pool import GTMPool
    gtm = mock.MagicMock()
    return GTMPool(gtm, 'Common', local_cluster_name=CLUSTER, cluster_digital_asset_id=UID), gtm


def test_new_pool_created_with_monitor_and_members_in_one_request():
    mgr, gtm = _pool_mgr()
    snapshot = {'pools': set(), 'pool_members': {}}

    mgr.create_pool(_pool_cfg(), '', skip_member_validation=True, snapshot=snapshot)

    gtm.pools.a_s.a.exists.assert_not_called()
    kwargs = gtm.pools.a_s.a.create.call_args[1]
    assert kwargs['monitor'] == '/Common/tcp'
    assert kwargs['members'] == [{'name': m, 'partition': 'Common'} for m in MEMBERS]
    gtm.pools.a_s.a.create.return_value.members_s.member.create.assert_not_called()
    assert POOL in snapshot['pools']


def test_pool_falls_back_to_per_object_path_when_inline_create_rejected():
    mgr, gtm = _pool_mgr()
    gtm.pools.a_s.a.create.side_effect = [Exception('409 already exists'), mock.MagicMock()]
    gtm.pools.a_s.a.exists.return_value = False

    mgr.create_pool(_pool_cfg(), '', skip_member_validation=True,
                    snapshot={'pools': set(), 'pool_members': {}})

    assert gtm.pools.a_s.a.create.call_count == 2
    assert 'members' not in gtm.pools.a_s.a.create.call_args[1]


def test_existing_pool_only_gets_members_missing_from_snapshot():
    mgr, gtm = _pool_mgr()
    pl = gtm.pools.a_s.a.load.return_value
    pl.monitor = '/Common/tcp'
    pl.fallbackMode = 'return-to-dns'
    pl.fallbackIp = 'any'
    pl.loadBalancingMode = 'round-robin'
    snapshot = {'pools': {POOL}, 'pool_members': {POOL: {MEMBERS[0]}}}

    mgr.create_pool(_pool_cfg(), '', skip_member_validation=True, snapshot=snapshot)

    gtm.pools.a_s.a.exists.assert_not_called()
    gtm.pools.a_s.a.create.assert_not_called()
    created = [c[1]['name'] for c in pl.members_s.member.create.call_args_list]
    assert created == [MEMBERS[1]]


def _wideip_mgr():
    from f5_ctlr_agent.gtm.wideip import GTMWideIP
    gtm = mock.MagicMock()
    return GTMWideIP(gtm, 'Common', local_cluster_name=CLUSTER, cluster_digital_asset_id=UID), gtm


_WIP = {'name': 'app.example.com', 'LoadBalancingMode': 'round-robin', 'aliases': ['a.example.com']}
_NEW_POOLS = {'p': {'name': 'app.example.com', 'partition': 'Common', 'ratio': 1, 'order': 0}}


def test_new_wideip_created_with_pools_and_owner_in_one_request():
    mgr, gtm = _wideip_mgr()
    snapshot = {'wideips': set()}

    mgr.create_wideip(_WIP, dict(_NEW_POOLS), snapshot=snapshot)

    gtm.wideips.a_s.a.exists.assert_not_called()
    kwargs = gtm.wideips.a_s.a.create.call_args[1]
    assert kwargs['pools'][0]['name'] == POOL
    assert UID in kwargs['description']
    assert kwargs['aliases'] == ['a.example.com']
    assert 'app.example.com' in snapshot['wideips']


def test_rejected_inline_wideip_still_hits_ownership_guard():
    mgr, gtm = _wideip_mgr()
    gtm.wideips.a_s.a.create.side_effect = Exception('409 already exists')
    gtm.wideips.a_s.a.exists.return_value = True
    gtm.wideips.a_s.a.load.return_value.description = 'managed-by: ebc | cluster: other-uid9'

    mgr.create_wideip(_WIP, dict(_NEW_POOLS), snapshot={'wideips': set()})

    gtm.wideips.a_s.a.load.return_value.update.assert_not_called()


def _delete_pool(member_names, uid_members_owned=True):
    mgr, gtm = _pool_mgr()
    pool = gtm.pools.a_s.a.load.return_value
    members = []
    for name in member_names:
        m = mock.MagicMock()
        m.name = name
        members.append(m)
    pool.members_s.get_collection.return_value = members
    gtm.wideips.a_s.a.exists.return_value = False  # wideIP detach is a no-op
    config = {'Common': {'wideIPs': [{'name': 'app.example.com', 'pools': [
        {'name': 'app.example.com', 'members': ['10.1.0.1:80'], 'DataServer': '10.200.0.1'}]}]}}
    mgr.delete_pool('app.example.com', 'app.example.com', working_config=config)
    return pool, members, config


def test_pool_with_only_our_members_is_deleted_without_member_calls():
    pool, members, config = _delete_pool(MEMBERS)

    pool.delete.assert_called_once()
    for m in members:
        m.delete.assert_not_called()
    pool.members_s.get_collection.assert_called_once()
    assert config['Common']['wideIPs'][0]['pools'] == []


def test_pool_with_foreign_members_keeps_them_and_stays():
    pool, members, _ = _delete_pool([MEMBERS[0], 'server_other_clu_10_9_9_9:vs-1'])

    members[0].delete.assert_called_once()
    members[1].delete.assert_not_called()
    pool.delete.assert_not_called()
