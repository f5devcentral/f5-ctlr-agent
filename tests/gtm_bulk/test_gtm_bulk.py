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
