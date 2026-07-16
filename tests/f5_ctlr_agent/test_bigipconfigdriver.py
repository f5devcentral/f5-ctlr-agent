#!/usr/bin/env python

# Copyright (c) 2018-2021 F5 Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from copy import deepcopy
import json
import logging
import os
import shutil
from string import Template
import sys
import threading
import time

from f5_cccl.exceptions import F5CcclValidationError

import pytest

from .. import bigipconfigdriver

_args_app_name = ['bigipconfigdriver.py']

_cloud_config = {
    'bigip': {
        'username': 'test',
        'url': 'https://127.0.0.1',
        'password': 'admin',
        'partition': 'test'
    },
    'resources': {
        "test": {
            'virtualServer': {
                'frontend': {
                    'virtualServerName': 'test.service',
                    'partition': 'test',
                    'virtualAddress': {
                        'bindAddr': '127.0.0.1',
                        'port': 8080
                    },
                    'mode': 'http',
                    'balance': 'round-robin'
                },
                'backend': {
                    'poolMemberAddrs': [
                        '192.168.0.1',
                        '192.168.0.2'
                    ],
                    'serviceName': 'myService',
                    'servicePort': 80
                }
            }
        }
    },
    'global': {
        'verify-interval': 0.25,
        'log-level': 'INFO'
    }
}

_expected_bigip_config = {
    'network': {},
    'ltm': {
        'test.service': {
            'virtual_address': '127.0.0.1',
            'name': 'test.service',
            'partition': 'test',
            'virtual': {
                'disabled': False,
                'profiles': [
                    {
                        'partition': 'Common',
                        'name': 'http'
                    }
                ],
                'pool': '/test/test.service',
                'ipProtocol': 'tcp',
                'destination': '/test/127.0.0.1:8080',
                'enabled': True,
                'sourceAddressTranslation': {
                    'type': 'automap'
                }
            },
            'health': [],
            'nodes': {
                '192.168.0.2': {
                    'state': 'user-up',
                    'session': 'user-enabled'
                },
                '192.168.0.1': {
                    'state': 'user-up',
                    'session': 'user-enabled'
                }
            },
            'pool': {
                'monitor': None,
                'loadBalancingMode': 'round-robin'
            }
        }
    }
}


class MockMgr(bigipconfigdriver.CloudServiceManager):
    def __init__(self, fail=False, notify_event=None, notify_after=0,
                 handle_results=None):
        self._partition = _cloud_config['bigip']['partition']
        self.calls = 0
        self._fail = fail
        self._notify_event = notify_event
        self._notify_after = notify_after
        self._handle_results = handle_results
        self._schema = None

    def get_partition(self):
        return self._partition

    def _apply_ltm_config(self, cfg):
        return self._apply_config(cfg)

    def _apply_net_config(self, cfg):
        return self._apply_config(cfg)

    def _apply_config(self, cfg):
        expected_bigip_config = json.loads(json.dumps(cfg))
        actual_bigip_config = json.loads(json.dumps(cfg))
        assert expected_bigip_config == actual_bigip_config

        self.calls = self.calls + 1

        if self._notify_event and self.calls == self._notify_after:
            self._notify_event.set()

        if self._handle_results:
            self._handle_results()
        else:
            if self._fail:
                self._fail = False
                raise F5CcclValidationError

        return 0


class MockEventHandler():
    def __init__(self):
        pass

    def on_change(self):
        pass


def test_handleargs_noargs(capsys):
    expected = "usage: bigipconfigdriver.py [-h] --config-file CONFIG_FILE\n"\
               "bigipconfigdriver.py: error:"\
               " argument --config-file is required\n"

    sys.argv[0:] = _args_app_name

    with pytest.raises(SystemExit):
        bigipconfigdriver._handle_args()

    out, err = capsys.readouterr()
    assert '' == out
    assert expected == err


def test_handleargs_notfilepath():
    sys.argv[0:] = _args_app_name
    sys.argv.extend(['--config-file', '/tmp/not-a-file/'])

    with pytest.raises(bigipconfigdriver.ConfigError) as eio:
        bigipconfigdriver._handle_args()

    assert eio.value.message == 'must provide a file path'


def test_handleargs_unexpected(capsys):
    expected = "usage: bigipconfigdriver.py [-h] --config-file CONFIG_FILE\n"\
               "bigipconfigdriver.py: error:"\
               " unrecognized arguments: --bad-arg\n"

    sys.argv[0:] = _args_app_name
    sys.argv.extend(['--config-file', '/tmp/file'])
    sys.argv.extend(['--bad-arg'])

    with pytest.raises(SystemExit):
        bigipconfigdriver._handle_args()

    out, err = capsys.readouterr()
    assert '' == out
    assert expected == err


def test_handleargs_expected():
    sys.argv[0:] = _args_app_name
    sys.argv.extend(['--config-file', '/tmp/.././tmp/file'])

    args = bigipconfigdriver._handle_args()

    assert args.config_file == '/tmp/file'


# IntervalTimer tests
def test_interval_init():
    def cb():
        pass

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(0, cb)

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(-1, cb)

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(-100, cb)

    with pytest.raises(ValueError):
        bigipconfigdriver.IntervalTimer("hello", cb)

    with pytest.raises(TypeError):
        bigipconfigdriver.IntervalTimer(0.1)

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(0.1, None)

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(0.1, "hello")


def test_interval_repeat():
    counter = {'times': 0}
    event = threading.Event()

    def intervalCb():
        counter['times'] = counter['times'] + 1
        if 5 == counter['times']:
            event.set()

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, intervalCb)
        assert interval is not None
        assert interval.is_running() is False

        interval.start()
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        interval.stop()
        assert interval.is_running() is False

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        interval.stop()
        assert interval.is_running() is False

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval.is_running() is True

        interval.stop()
        assert interval.is_running() is False
    finally:
        assert interval is not None


def test_interval_startstop():
    def cb():
        pass

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, cb)
        assert interval is not None
        assert interval.is_running() is False

        interval.start()
        assert interval.is_running() is True

        interval.stop()
        assert interval.is_running() is False
    finally:
        assert interval is not None


def test_interval_nostartstop():
    def cb():
        pass

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, cb)
        assert interval is not None
        assert interval.is_running() is False

        interval.stop()
        assert interval.is_running() is False

    except RuntimeError:
        assert interval.is_alive() is False
    finally:
        assert interval is not None


# ConfigWatcher tests
def test_configwatcher_init(request):
    expected_dir_template = Template('/tmp/$pid')
    expected_dir = expected_dir_template.substitute(pid=os.getpid())
    expected_file = expected_dir + '/file'

    def fin():
        shutil.rmtree(expected_dir, ignore_errors=True)

    request.addfinalizer(fin)

    watcher = bigipconfigdriver.ConfigWatcher(expected_file,
                                              MockEventHandler().on_change)

    assert watcher._config_file == expected_file
    assert watcher._config_dir == expected_dir
    assert watcher._config_stats is None
    assert watcher._polling is False
    assert watcher._running is False

    # Test with file on created
    expected_digest = '\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04' + \
        '\xe9\x80\t\x98\xec\xf8B~'

    os.mkdir(expected_dir)
    with open(expected_file, 'w+'):
        os.utime(expected_file, None)

    watcherExist = bigipconfigdriver.ConfigWatcher(
            expected_file,
            MockEventHandler().on_change)

    assert watcherExist._config_file == expected_file
    assert watcherExist._config_dir == expected_dir
    assert watcherExist._config_stats == expected_digest
    assert watcher._polling is False
    assert watcher._running is False


def test_configwatcher_shouldwatch():
    watch_file_template = Template('/tmp/$pid')
    watch_file = watch_file_template.substitute(pid=os.getpid())

    watcher = bigipconfigdriver.ConfigWatcher(watch_file,
                                              MockEventHandler().on_change)

    assert watcher._should_watch(watch_file) is True

    assert watcher._should_watch('/tmp/not-config-file') is False


def test_configwatcher_loop(request):
    watch_dir_template = Template('/tmp/$pid')
    watch_dir = watch_dir_template.substitute(pid=os.getpid())
    watch_file = watch_dir + '/file'

    def fin():
        shutil.rmtree(watch_dir, ignore_errors=True)

    request.addfinalizer(fin)

    expected_changes = [True, True, False, True, True, True]
    expected_digests = [
        '\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~',
        '\xd7-\x16\xde\x92\xf2\xb6\xc1\x05\xce\xabj\x84\xcf\xcaz',
        '\xd7-\x16\xde\x92\xf2\xb6\xc1\x05\xce\xabj\x84\xcf\xcaz', None,
        '\xd7-\x16\xde\x92\xf2\xb6\xc1\x05\xce\xabj\x84\xcf\xcaz', None
    ]

    watcher = bigipconfigdriver.ConfigWatcher(watch_file,
                                              MockEventHandler().on_change)

    # loop will block and threading will introduce synchronization complexities
    # assuming pyinotify signals properly and only testing the _is_changed
    # function
    assert watcher._config_stats is None

    # IN_CREATE event
    os.mkdir(watch_dir)
    with open(watch_file, 'w+') as file_handle:
        (changed, md5sum) = watcher._is_changed()
        assert changed == expected_changes[0]
        assert md5sum == expected_digests[0]
        watcher._config_stats = md5sum

        file_handle.write('Senatus Populusque Romanus')

    # IN_CLOSE_WRITE event
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[1]
    assert md5sum == expected_digests[1]
    watcher._config_stats = md5sum

    # IN_CLOSE_WRITE no change
    with open(watch_file, 'w') as file_handle:
        file_handle.write('Senatus Populusque Romanus')
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[2]
    assert md5sum == expected_digests[2]

    # IN_MOVED_FROM event
    shutil.move(watch_file, watch_dir + '/file2')
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[3]
    assert md5sum == expected_digests[3]
    watcher._config_stats = md5sum

    # IN_MOVED_TO event
    shutil.move(watch_dir + '/file2', watch_file)
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[4]
    assert md5sum == expected_digests[4]
    watcher._config_stats = md5sum

    # IN_DELETE event
    os.unlink(watch_file)
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[5]
    assert md5sum == expected_digests[5]


def test_confighandler_lifecycle():
    handler = None
    try:
        mgr = MockMgr()
        handler = bigipconfigdriver.ConfigHandler('/tmp/config', [mgr], 30)

        assert handler._thread in threading.enumerate()
        assert handler._thread.is_alive() is True
        assert handler._pending_reset is False
        assert handler._stop is False
        assert handler._managers == [mgr]
        assert handler._config_file == '/tmp/config'
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread not in threading.enumerate()
        assert handler._thread.is_alive() is False
        assert handler._stop is True


def test_parse_config(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr], 30)

        obj = {}
        obj['field1'] = 'one'
        obj['field_string'] = 'string'
        obj['field_number'] = 10

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        assert r is not None
        assert r['field1'] == obj['field1']
        assert r['field_string'] == obj['field_string']
        assert r['field_number'] == obj['field_number']
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_is_non_retryable_error():
    assert bigipconfigdriver._is_non_retryable_error(
        'BIG-IP connection error: 401 Authorization Required'
    ) is True
    assert bigipconfigdriver._is_non_retryable_error(
        'GTM BIG-IP connection error: 403 Forbidden'
    ) is True
    assert bigipconfigdriver._is_non_retryable_error(
        'BIG-IP connection error: 400 username and password must not be null'
    ) is True
    assert bigipconfigdriver._is_non_retryable_error(
        'BIG-IP connection error: timed out while connecting'
    ) is False


def test_retry_backoff_fail_fast_non_retryable_error():
    def cb(_):
        return (False, 'BIG-IP connection error: 401 Authorization Required', True)

    with pytest.raises(bigipconfigdriver.ConfigError) as exc:
        bigipconfigdriver._retry_backoff(cb)

    assert 'non-retryable error' in str(exc.value)


def test_retry_backoff_retries_transient_then_succeeds(monkeypatch):
    call_count = {'value': 0}

    def no_sleep(_):
        return None

    def cb(_):
        call_count['value'] += 1
        if call_count['value'] < 3:
            return (False, 'BIG-IP connection error: timeout')
        return (True, 'connected')

    monkeypatch.setattr(bigipconfigdriver.time, 'sleep', no_sleep)

    result = bigipconfigdriver._retry_backoff(cb)

    assert result == 'connected'
    assert call_count['value'] == 3


def test_get_credentials_returns_none_without_bigip_creds(monkeypatch):
    monkeypatch.setattr(bigipconfigdriver, 'get_credentials_from_socket', lambda _: {})
    monkeypatch.setattr(bigipconfigdriver, 'get_credentials_from_env', lambda: None)
    monkeypatch.setattr(bigipconfigdriver, 'get_gtm_credentials_from_env', lambda: None)

    result = bigipconfigdriver.get_credentials('/tmp/secure_ebc.sock')

    assert result is None


def test_get_credentials_defaults_gtm_to_bigip(monkeypatch):
    monkeypatch.setattr(
        bigipconfigdriver,
        'get_credentials_from_socket',
        lambda _: {'bigip_username': 'user1', 'bigip_password': 'pass1'})
    monkeypatch.setattr(bigipconfigdriver, 'get_credentials_from_env', lambda: None)
    monkeypatch.setattr(bigipconfigdriver, 'get_gtm_credentials_from_env', lambda: None)

    result = bigipconfigdriver.get_credentials('/tmp/secure_ebc.sock')

    assert result['bigip_username'] == 'user1'
    assert result['bigip_password'] == 'pass1'
    assert result['gtm_username'] == 'user1'
    assert result['gtm_password'] == 'pass1'


def test_handle_credentials_raises_when_credentials_invalid(monkeypatch):
    monkeypatch.setattr(bigipconfigdriver, 'get_credentials', lambda _: None)
    config = {
        'credential_socket': '/tmp/secure_ebc.sock',
        'bigip': {'url': 'https://10.0.0.1', 'partitions': ['Common']}
    }

    with pytest.raises(bigipconfigdriver.ConfigError):
        bigipconfigdriver._handle_credentials(config)


def test_handle_global_config(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['global'] = {'log-level': 'WARNING',
                         'verify-interval': 10,
                         'vxlan-partition': 'test'}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, vx_p, local_cluster_name, cluster_digital_asset_id = \
            bigipconfigdriver._handle_global_config(r)
        assert verify_interval == 10
        assert level == logging.WARNING
        assert vx_p == 'test'
        assert local_cluster_name is None
        assert cluster_digital_asset_id is None

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_defaults(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['global'] = {}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, vx_p, local_cluster_name, cluster_digital_asset_id = \
            bigipconfigdriver._handle_global_config(r)
        assert verify_interval == bigipconfigdriver.DEFAULT_VERIFY_INTERVAL
        assert level == bigipconfigdriver.DEFAULT_LOG_LEVEL
        assert vx_p is None
        assert local_cluster_name is None
        assert cluster_digital_asset_id is None

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_bad_string_log_level(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {"global": {"log-level": "everything", "verify-interval": 100}}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, _, _, _ = bigipconfigdriver._handle_global_config(r)
        assert verify_interval == 100
        assert level == bigipconfigdriver.DEFAULT_LOG_LEVEL

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_number_log_level(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {"global": {"log-level": 55, "verify-interval": 100}}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, _, _, _ = bigipconfigdriver._handle_global_config(r)
        assert verify_interval == 100
        assert level == bigipconfigdriver.DEFAULT_LOG_LEVEL

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_negative_verify_interval(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {"global": {"log-level": "ERROR", "verify-interval": -1}}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, _, _, _ = bigipconfigdriver._handle_global_config(r)
        assert verify_interval == bigipconfigdriver.DEFAULT_VERIFY_INTERVAL
        assert level == logging.ERROR

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_string_verify_interval(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {"global": {"log-level": "ERROR", "verify-interval": "hundred"}}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, _, _, _ = bigipconfigdriver._handle_global_config(r)
        assert verify_interval == bigipconfigdriver.DEFAULT_VERIFY_INTERVAL
        assert level == logging.ERROR

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'username': 'admin', 'password': 'changeme',
                        'url': 'http://10.10.10.10:443',
                        'partitions': ['common', 'velcro']}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        try:
            host, port = bigipconfigdriver._handle_bigip_config(r)
            assert host == '10.10.10.10'
            assert port == 443
        except:
            assert 0

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_bigip(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_username(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'password': 'changeme',
                        'url': 'http://10.10.10.10:443',
                        'partitions': ['common', 'velcro']}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_password(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'username': 'admin',
                        'url': 'http://10.10.10.10:443',
                        'partitions': ['common', 'velcro']}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_url(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'username': 'admin', 'password': 'changeme',
                        'partitions': ['common', 'velcro']}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_partitions(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'username': 'admin', 'password': 'changeme',
                        'url': 'http://10.10.10.10:443',
                        'partitions': []}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_vxlan_config(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['vxlan-fdb'] = {'name': 'vxlan0',
                            'records': [
                                {'name': '0a:0a:ac:10:1:5',
                                 'endpoint': '198.162.0.1'},
                                {'name': '0a:0a:ac:10:1:6',
                                 'endpoint': '198.162.0.2'}
                            ]}
        obj['vxlan-arp'] = {'arps': [
                                {'macAddress': '0a:0a:ac:10:1:5',
                                 'ipAddress': '1.2.3.4',
                                 'name': '1.2.3.4'}
                                ]
                            }

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        try:
            bigipconfigdriver._handle_vxlan_config(r)
        except:
            assert 0

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_vxlan_config_missing_vxlan_name(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['vxlan-fdb'] = {'records': [
                                {'name': '0a:0a:ac:10:1:5',
                                 'endpoint': '198.162.0.1'},
                                {'name': '0a:0a:ac:10:1:6',
                                 'endpoint': '198.162.0.2'}
                            ]}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_vxlan_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_vxlan_config_missing_vxlan_records(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['vxlan-fdb'] = {'name': 'vxlan0'}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_vxlan_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def _raise_value_error():
    raise ValueError('No JSON object could be decoded', 0)


def test_confighandler_reset_json_error(request):
    exception = _raise_value_error
    common_confighandler_reset(request, exception)


def _raise_cccl_error():
    raise F5CcclValidationError('Generic CCCL Error')


def test_confighandler_reset_validation_error(request):
    exception = _raise_cccl_error
    common_confighandler_reset(request, exception)


def _raise_unexpected_error():
    raise Exception('Unexpected Failure')


def test_confighandler_reset_unexpected_error(request):
    exception = _raise_unexpected_error
    common_confighandler_reset(request, exception)


def common_confighandler_reset(request, exception):
    handler = None
    mgr = None
    flags = {'valid_interval_state': True}

    try:
        # Force an error on the fourth invocation, verify interval timer
        # is disabled during retries
        def handle_results():
            if mgr.calls == 4:
                # turn on retries by returning an error
                exception()

            valid_interval_state = flags['valid_interval_state']
            if mgr.calls == 1 or mgr.calls == 5:
                # verify interval timer is off due to previous error
                if valid_interval_state:
                    valid_interval_state =\
                        (handler._interval.is_running() is False)
            else:
                if valid_interval_state:
                    valid_interval_state =\
                        (handler._interval.is_running() is True)
            flags['valid_interval_state'] = valid_interval_state

        event = threading.Event()
        mgr = MockMgr(notify_event=event, notify_after=5,
                      handle_results=handle_results)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        # keep the interval timer from expiring during retries
        interval_time = 0.6
        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr],
                                                  interval_time)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert mgr.calls == 0

        obj = deepcopy(_cloud_config)
        obj['global']['verify-interval'] = interval_time
        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        assert handler._thread.is_alive() is True

        handler.notify_reset()
        time.sleep(0.1)
        assert mgr.calls == 1
        assert flags['valid_interval_state'] is True

        handler.notify_reset()
        time.sleep(0.1)
        assert mgr.calls == 2
        assert flags['valid_interval_state'] is True

        handler.notify_reset()
        time.sleep(0.1)
        assert mgr.calls == 3
        assert flags['valid_interval_state'] is True

        # in the failure case, the exception will be caught
        # and the backoff_timer will be set.  Verify the
        # backoff time has doubled.
        handler._backoff_time = 0.6

        handler.notify_reset()
        time.sleep(0.1)
        assert mgr.calls == 4
        assert flags['valid_interval_state'] is True

        assert handler._backoff_time == 1.2
        assert handler._backoff_timer is not None

        assert handler._interval.is_running() is False

        handler.notify_reset()
        time.sleep(0.1)
        event.wait(30)
        assert event.is_set() is True
        assert flags['valid_interval_state'] is True

        # After a successful call, we should be back to using the
        # interval timer
        assert handler._backoff_time == 1
        assert handler._backoff_timer is None

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_confighandler_execution(request):
    handler = None
    try:
        # Each execution of the regenerate_config_f5() should take as
        # long as the interval timer to verify we adjust for this.
        interval_time = 0.20

        def handle_results():
            time.sleep(interval_time)

        mgr = MockMgr(handle_results=handle_results)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        # make the interval timer the same as the execution time
        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr],
                                                  interval_time)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert mgr.calls == 0

        obj = deepcopy(_cloud_config)
        obj['global']['verify-interval'] = interval_time
        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        assert handler._thread.is_alive() is True

        # The time spent in the execution of the regenerate_config_f5() should
        # not delay the next interval.  So we expect to have at least
        # 'total_time / interval' number of calls.
        total_time = 1.00
        # If we didn't account for execution time, we'd get about 50% of
        # the expected, so we'll use 75% to account for clock slop.
        min_expected_calls = int(0.75 * total_time / interval_time)
        handler.notify_reset()
        time.sleep(total_time)
        assert mgr.calls >= min_expected_calls

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_confighandler_checkpoint(request):
    handler = None
    try:
        event = threading.Event()
        mgr = MockMgr(notify_event=event, notify_after=5)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr],
                                                  0.25)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert mgr.calls == 0

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(_cloud_config, f)

        assert handler._thread.is_alive() is True

        assert handler._interval.is_running() is False
        handler.notify_reset()
        time.sleep(0.2)
        assert handler._interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False
        assert handler._interval.is_running() is False


def test_confighandler_checkpointstopafterfailure(request):
    handler = None
    try:
        event = threading.Event()
        mgr = MockMgr(fail=True, notify_event=event, notify_after=5)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr],
                                                  0.25)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert mgr.calls == 0

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(_cloud_config, f)

        assert handler._thread.is_alive() is True

        assert handler._interval.is_running() is False

        # get rid of the real notify reset so we only do_reset once in
        # this test
        def p():
            pass
        handler.notify_reset = p
        handler._condition.acquire()
        handler._pending_reset = True
        handler._condition.notify()
        handler._condition.release()
        time.sleep(0.2)

        # should be false here because an invalid config stops the interval
        assert handler._interval.is_running() is False
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False
        assert handler._interval.is_running() is False


def test_confighandler_backoff_time(request):
    try:
        handler = bigipconfigdriver.ConfigHandler({}, {}, 0.25)
        backoff = handler.handle_backoff
        handler._backoff_time = .025
        handler._max_backoff_time = .1

        backoff()
        # first call doubles _backoff_time _backoff_timer should have original
        # value for its interval
        assert handler._backoff_timer.interval == .025
        assert handler._backoff_time == .05
        backoff()
        # values should not change since we already have a timer set
        assert handler._backoff_timer.interval == .025
        assert handler._backoff_time == .05
        handler._backoff_timer = None
        backoff()
        # call doubles _backoff_time since we cleared previous timer
        assert handler._backoff_timer.interval == .05
        assert handler._backoff_time == .1
        handler._backoff_timer = None
        backoff()
        # hit _max_backoff_time so _backoff_time does not increase
        assert handler._backoff_timer.interval == .1
        assert handler._backoff_time == .1

    finally:
        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False
        assert handler._interval.is_running() is False


class MockApplyConfigMgr(bigipconfigdriver.CloudServiceManager):

    def __init__(self, returns):
        self._returns = returns
        self._schema = None

    def _apply_ltm_config(self, cfg):
        return self._apply_config(cfg)

    def _apply_net_config(self, cfg):
        return self._apply_config(cfg)

    def _apply_config(self, cfg):
        val = self._returns.pop(0)
        if type(val) is 'exceptions.Exception':
            raise val
        else:
            return val

    def get_partition(self):
        return 'test'


def test_confighandler_backoff_timer(request):
    SLEEP_INTERVAL = 0.1
    INTERVAL = 5
    TEST_VECTORS = [
        [1, 0, 2, 3, 4]
    ]

    config_template = Template('/tmp/config.$pid')
    config_file = config_template.substitute(pid=os.getpid())
    obj = deepcopy(_cloud_config)
    obj['global']['verify-interval'] = INTERVAL
    with open(config_file, 'w+') as f:
        def fin():
            os.unlink(config_file)
        request.addfinalizer(fin)
        json.dump(obj, f)

    for vector in TEST_VECTORS:
        try:
            mgr = MockApplyConfigMgr(vector)

            handler = bigipconfigdriver.ConfigHandler(
                config_file, [mgr], INTERVAL
            )
            time.sleep(SLEEP_INTERVAL)

            assert handler._thread.is_alive() is True

            # regenerate_config_f5 had an error so create a backoff timer
            # with an arbitrary backoff time.
            handler._backoff_time = 64
            handler.notify_reset()
            time.sleep(SLEEP_INTERVAL)
            assert handler._backoff_timer.interval == 64
            assert handler._backoff_timer.finished.is_set() is False
            prev_timer = handler._backoff_timer

            # regenerate_config_f5 did not have an error on reconfig so we
            # should cancel and cleanup backoff timer.
            handler.notify_reset()
            time.sleep(SLEEP_INTERVAL)
            assert handler._backoff_timer is None
            assert prev_timer.finished.is_set() is True

            # regenerate_config_f5 had an error on reconfig so create a new
            # backoff timer with another arbitrary backoff time.
            handler._backoff_time = 0.5
            handler.notify_reset()
            time.sleep(SLEEP_INTERVAL)
            assert handler._backoff_timer.interval == 0.5
            assert handler._backoff_timer.finished.is_set() is False
            prev_timer = handler._backoff_timer

            # regenerate_config_f5 had another error on reconfig but there is
            # already a backoff timer so do not create a new backoff timer.
            handler.notify_reset()
            time.sleep(SLEEP_INTERVAL)
            assert handler._backoff_timer.interval == 0.5
            assert handler._backoff_timer.finished.is_set() is False
            assert handler._backoff_timer is prev_timer

            # Let the back off timer play out and call its cb resetting the
            # timer reference and calling notify_reset. regenerate_config_f5
            # will have had an error so a new timer should be created.
            handler._backoff_time = 32
            time.sleep(0.6)
            assert handler._backoff_timer.interval == 32
            assert handler._backoff_timer.finished.is_set() is False
            assert handler._backoff_timer is not prev_timer

        finally:
            handler.stop()
            handler._thread.join(30)
            assert handler._thread.is_alive() is False
            assert handler._interval.is_running() is False


# ─────────────────────────────────────────────────────────────
# Enhancement unit tests (2.4 spec additions)
# ─────────────────────────────────────────────────────────────

from f5_ctlr_agent.gtm.utils import GTMUtils
from f5_ctlr_agent.gtm.pool import GTMPool
from f5_ctlr_agent.gtm.wideip import GTMWideIP


class _DummyMemberResource:
    def exists(self, **kwargs):
        return False

    def create(self, **kwargs):
        return None


class _DummyPoolObject:
    def __init__(self, fallback_mode='none', lb_mode='round-robin'):
        self.monitor = ''
        self.fallbackMode = fallback_mode
        self.fallbackIp = ''
        self.loadBalancingMode = lb_mode
        self.members_s = type('Members', (), {'member': _DummyMemberResource()})()

    def update(self):
        return None


class _DummyPoolCollection:
    def __init__(self):
        self.last_create_kwargs = None

    def exists(self, **kwargs):
        return False

    def create(self, **kwargs):
        self.last_create_kwargs = kwargs
        return _DummyPoolObject(
            fallback_mode=kwargs.get('fallbackMode', 'none'),
            lb_mode=kwargs.get('loadBalancingMode', 'round-robin'))

    def load(self, **kwargs):
        return _DummyPoolObject()


class _DummyGTM:
    def __init__(self, pool_collection):
        self.pools = type('Pools', (), {'a_s': type('AS', (), {'a': pool_collection})()})()


class _DummyWideIPObject:
    def __init__(self, pool_lb_mode='round-robin', description=None, aliases=None):
        self.poolLbMode = pool_lb_mode
        self.description = description
        self.aliases = aliases or []
        self.lastResortPool = 'none'
        self.raw = {'pools': []}

    def update(self):
        return None


class _DummyWideIPCollection:
    def __init__(self):
        self.last_create_kwargs = None

    def exists(self, **kwargs):
        return False

    def create(self, **kwargs):
        self.last_create_kwargs = kwargs
        return _DummyWideIPObject(
            pool_lb_mode=kwargs.get('poolLbMode', 'round-robin'),
            description=kwargs.get('description'),
            aliases=kwargs.get('aliases', []))

    def load(self, **kwargs):
        return _DummyWideIPObject()


class _DummyGTMWideIP:
    def __init__(self, wideip_collection):
        self.wideips = type('WideIPs', (), {'a_s': type('AS', (), {'a': wideip_collection})()})()


# --- Enhancement 1: DNS Suffix ---

def test_build_wideip_name_with_suffix():
    """WideIP name is normalized hostname + '.' + suffix."""
    result = GTMUtils.build_wideip_name('app.example.com', 'gslb1.fr.net.intra')
    assert result == 'app-example-com.gslb1.fr.net.intra'


def test_build_wideip_name_without_suffix():
    """Without suffix the original domain-name is returned unchanged."""
    result = GTMUtils.build_wideip_name('app.example.com')
    assert result == 'app.example.com'


def test_pre_process_gtm_dns_suffix_builds_name():
    """pre_process_gtm constructs WideIP name from domain-name + domain-suffix."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'domain-name': 'foo.com',
                    'domain-suffix': 'gslb1.fr.net.intra',
                    'LoadBalancingMode': 'round-robin',
                    'pools': [],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    assert config['Common']['wideIPs'][0]['name'] == 'foo-com.gslb1.fr.net.intra'


def test_pre_process_gtm_domain_name_without_suffix():
    """When only domain-name is set and no existing name, uses domain-name as name."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'domain-name': 'foo.com',
                    'LoadBalancingMode': 'round-robin',
                    'pools': [],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    assert config['Common']['wideIPs'][0]['name'] == 'foo.com'


# --- Enhancement 2: Alias support (tested via pre_process passthrough) ---

def test_pre_process_gtm_preserves_aliases():
    """pre_process_gtm leaves existing aliases field untouched."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'aliases': ['alias1.example.com', 'alias2.example.com'],
                    'LoadBalancingMode': 'round-robin',
                    'pools': [],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    assert config['Common']['wideIPs'][0]['aliases'] == [
        'alias1.example.com', 'alias2.example.com'
    ]


# --- Enhancement 3: Load Balancing Method ---

def test_pre_process_gtm_fallback_ip_explicit():
    """Fallback IP method with explicit IP sets pool fallbackMode and fallback-ip."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'load-balance': {'method': 'Fallback IP', 'fallback-ip': '10.0.0.5'},
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {'name': 'pool1', 'fallbackMode': 'none',
                         'LoadBalancingMode': 'round-robin', 'members': []},
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert pool['fallbackMode'] == 'fallback-ip'
    assert pool['fallback-ip'] == '10.0.0.5'


def test_pre_process_gtm_fallback_ip_explicit_camel_case():
    """Camel-case fallbackIp is accepted as an explicit fallback address."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'load-balance': {'method': 'Fallback IP', 'fallbackIp': '10.0.0.7'},
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {
                            'name': 'pool1', 'fallbackMode': 'none',
                            'LoadBalancingMode': 'round-robin',
                            'DataServer': '10.1.0.1',
                            'members': ['10.1.0.1|10.2.0.3|80'],
                        },
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert pool['fallbackMode'] == 'fallback-ip'
    assert pool['fallback-ip'] == '10.0.0.7'


def test_pre_process_gtm_fallback_ip_uses_first_member():
    """When fallback-ip is absent, uses first member IP as fallback."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'load-balance': {'method': 'Fallback IP'},
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {
                            'name': 'pool1', 'fallbackMode': 'none',
                            'LoadBalancingMode': 'round-robin',
                            'DataServer': '10.1.0.1',
                            'members': ['10.1.0.1|10.2.0.3|80'],
                        },
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert pool['fallbackMode'] == 'fallback-ip'
    assert pool['fallback-ip'] == '10.2.0.3'


def test_pre_process_gtm_fallback_ip_empty_uses_first_member():
    """Blank fallback-ip uses the first member IPv4 when available."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'load-balance': {'method': 'Fallback IP', 'fallback-ip': '   '},
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {
                            'name': 'pool1', 'fallbackMode': 'none',
                            'LoadBalancingMode': 'round-robin',
                            'DataServer': '10.1.0.1',
                            'members': ['10.1.0.1|10.2.0.3|80'],
                        },
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert pool['fallbackMode'] == 'fallback-ip'
    assert pool['fallback-ip'] == '10.2.0.3'


def test_pre_process_gtm_fallback_ip_invalid_explicit_uses_first_member():
    """Invalid explicit fallback-ip falls back to the first member IPv4."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'load-balance': {'method': 'Fallback IP', 'fallback-ip': ' not-an-ip '},
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {
                            'name': 'pool1', 'fallbackMode': 'none',
                            'LoadBalancingMode': 'round-robin',
                            'DataServer': '10.1.0.1',
                            'members': ['10.1.0.1|10.2.0.3|80'],
                        },
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert pool['fallbackMode'] == 'fallback-ip'
    assert pool['fallback-ip'] == '10.2.0.3'


def test_pre_process_gtm_fallback_ip_empty_disables_invalid_mode():
    """Blank fallback-ip with no usable members does not leave pool in fallback-ip mode."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'load-balance': {'method': 'Fallback IP', 'fallback-ip': '   '},
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {'name': 'pool1', 'fallbackMode': 'fallback-ip',
                         'fallback-ip': '10.0.0.5',
                         'LoadBalancingMode': 'round-robin', 'members': []},
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert pool['fallbackMode'] == 'none'
    assert 'fallback-ip' not in pool


def test_pre_process_gtm_return_to_dns():
    """Return to DNS method sets pool fallbackMode to return-to-dns."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'load-balance': {'method': 'Return to DNS'},
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {'name': 'pool1', 'fallbackMode': 'none',
                         'LoadBalancingMode': 'round-robin', 'members': []},
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config)
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert pool['fallbackMode'] == 'return-to-dns'


def test_gtm_pool_create_uses_first_member_when_fallback_ip_missing():
    """create_pool uses first member IP when fallback-ip mode has no explicit IP."""
    pool_collection = _DummyPoolCollection()
    manager = GTMPool(_DummyGTM(pool_collection), 'Common')
    config = {
        'pools': [
            {
                'name': 'pool-fb-auto.example.com',
                'fallbackMode': 'fallback-ip',
                'LoadBalancingMode': 'round-robin',
                'DataServer': '10.1.0.1',
                'members': ['10.1.0.1|10.2.0.3|80'],
            }
        ]
    }

    manager.create_pool(config, monitors='')

    assert pool_collection.last_create_kwargs['fallbackMode'] == 'fallback-ip'
    assert pool_collection.last_create_kwargs["fallbackIp"] == '10.2.0.3'


def test_gtm_pool_create_uses_member_vs_reference_when_fallback_ip_missing():
    """create_pool derives fallback IP from BIG-IP member reference when needed."""
    pool_collection = _DummyPoolCollection()
    manager = GTMPool(_DummyGTM(pool_collection), 'Common')
    config = {
        'pools': [
            {
                'name': 'pool-fb-vs-ref.example.com',
                'fallbackMode': 'fallback-ip',
                'LoadBalancingMode': 'round-robin',
                'members': ['server_10_1_0_1:vs-10-2-0-3-80'],
            }
        ]
    }

    manager.create_pool(config, monitors='')

    assert pool_collection.last_create_kwargs['fallbackMode'] == 'fallback-ip'
    assert pool_collection.last_create_kwargs["fallbackIp"] == '10.2.0.3'


def test_gtm_pool_create_uses_cluster_qualified_vs_reference_when_fallback_ip_missing():
    """create_pool derives fallback IP from cluster-qualified VS member references."""
    pool_collection = _DummyPoolCollection()
    manager = GTMPool(_DummyGTM(pool_collection), 'Common')
    config = {
        'pools': [
            {
                'name': 'pool-fb-vs-ref-cluster.example.com',
                'fallbackMode': 'fallback-ip',
                'LoadBalancingMode': 'round-robin',
                'members': ['server_cluster-1_10_1_0_1:vs-cluster-1-10-2-0-3-80'],
            }
        ]
    }

    manager.create_pool(config, monitors='')

    assert pool_collection.last_create_kwargs['fallbackMode'] == 'fallback-ip'
    assert pool_collection.last_create_kwargs["fallbackIp"] == '10.2.0.3'


def test_gtm_pool_create_downgrades_when_fallback_ip_unusable():
    """create_pool downgrades mode when neither explicit nor derived fallback IP exists."""
    pool_collection = _DummyPoolCollection()
    manager = GTMPool(_DummyGTM(pool_collection), 'Common')
    config = {
        'pools': [
            {
                'name': 'pool-fb-empty.example.com',
                'fallbackMode': 'fallback-ip',
                'LoadBalancingMode': 'round-robin',
                'members': [],
            }
        ]
    }

    manager.create_pool(config, monitors='')

    assert pool_collection.last_create_kwargs['fallbackMode'] == 'return-to-dns'
    assert 'fallbackIp' not in pool_collection.last_create_kwargs


def test_gtm_pool_create_keeps_explicit_fallback_ip_mode():
    """create_pool keeps fallback-ip mode when a valid explicit fallback IP exists."""
    pool_collection = _DummyPoolCollection()
    manager = GTMPool(_DummyGTM(pool_collection), 'Common')
    config = {
        'pools': [
            {
                'name': 'pool-fb-explicit.example.com',
                'fallbackMode': 'fallback-ip',
                'fallbackIp': '10.10.10.10',
                'LoadBalancingMode': 'round-robin',
                'members': [],
            }
        ]
    }

    manager.create_pool(config, monitors='')

    assert pool_collection.last_create_kwargs['fallbackMode'] == 'fallback-ip'
    assert pool_collection.last_create_kwargs["fallbackIp"] == '10.10.10.10'


# --- Enhancement 4: GSLB server naming convention ---

def test_format_server_name_new_with_uid_and_namespace():
    """New naming: server_<UID>_<cluster>_<namespace>_<ip>."""
    result = GTMUtils.format_server_name(
        '10.155.15.101',
        local_cluster_name='cluster-west-1',
        digital_asset_id='bdee68ed-3157-44a7-a404-f3c311f5b0c3',
        namespace='test')
    assert result == 'server_bdee68ed-3157-44a7-a404-f3c311f5b0c3_cluster-west-1_test_10_155_15_101'


def test_format_server_name_new_no_namespace():
    """New naming without namespace: server_<UID>_<cluster>_<ip>."""
    result = GTMUtils.format_server_name(
        '10.1.0.1',
        local_cluster_name='cluster-1',
        digital_asset_id='bdee68ed-3157-44a7-a404-f3c311f5b0c3')
    assert result == 'server_bdee68ed-3157-44a7-a404-f3c311f5b0c3_cluster-1_10_1_0_1'


def test_format_server_name_legacy():
    """Fallback naming (no UID) uses server_<cluster>_<ip>."""
    result = GTMUtils.format_server_name('10.1.0.1', local_cluster_name='cluster-1')
    assert result == 'server_cluster-1_10_1_0_1'


def test_format_server_name_legacy_no_cluster():
    """Legacy naming with no cluster prefix."""
    result = GTMUtils.format_server_name('10.1.0.1')
    assert result == 'server_10_1_0_1'


def test_format_pool_name_with_uid():
    """Pool naming with UID includes UID and cluster in order."""
    result = GTMUtils.format_pool_name(
        'app.example.com',
        local_cluster_name='cluster-west-1',
        digital_asset_id='bdee68ed-3157-44a7-a404-f3c311f5b0c3')
    assert result == 'pool_bdee68ed-3157-44a7-a404-f3c311f5b0c3_cluster-west-1_app.example.com'


def test_format_pool_name_legacy():
    """Pool naming without UID follows the same pattern."""
    result = GTMUtils.format_pool_name('my-pool', local_cluster_name='cluster-1')
    assert result == 'pool_cluster-1_my-pool'


def test_format_pool_name_normalizes_pool_prefix():
    """Leading pool- from upstream config is stripped before formatting."""
    result = GTMUtils.format_pool_name(
        'pool-app.example.com',
        local_cluster_name='cluster-1',
        digital_asset_id='any-id')
    assert result == 'pool_any-id_cluster-1_app.example.com'


def test_format_pool_name_domain_only():
    """Pool naming with only domain uses pool_<domain>."""
    result = GTMUtils.format_pool_name('app.example.com')
    assert result == 'pool_app.example.com'


def test_format_vs_name_with_cluster_identifier():
    """VS naming with cluster uses vs-<cluster>-<ip>-<port>."""
    result = GTMUtils.format_vs_name('10.1.2.10:80', local_cluster_name='cluster-1')
    assert result == 'vs-cluster-1-10-1-2-10-80'


def test_format_vs_name_without_cluster_identifier():
    """VS naming without cluster uses vs-<ip>-<port>."""
    result = GTMUtils.format_vs_name('10.1.2.10:80')
    assert result == 'vs-10-1-2-10-80'


def test_wideip_create_stamps_description_with_cluster_and_uid():
    """WideIP description includes both local cluster and digital asset ID."""
    wideip_collection = _DummyWideIPCollection()
    manager = GTMWideIP(
        _DummyGTMWideIP(wideip_collection),
        'Common',
        local_cluster_name='cluster-1',
        cluster_digital_asset_id='uid-1')

    config = {
        'name': 'app.example.com',
        'LoadBalancingMode': 'round-robin',
    }

    manager.create_wideip(config, {})

    assert wideip_collection.last_create_kwargs['description'] == 'managed-by: cis | cluster: cluster-1-uid-1'


def test_wideip_create_stamps_description_with_cluster_only():
    """WideIP description includes local cluster when digital asset ID is absent."""
    wideip_collection = _DummyWideIPCollection()
    manager = GTMWideIP(
        _DummyGTMWideIP(wideip_collection),
        'Common',
        local_cluster_name='cluster-1',
        cluster_digital_asset_id=None)

    config = {
        'name': 'app.example.com',
        'LoadBalancingMode': 'round-robin',
    }

    manager.create_wideip(config, {})

    assert wideip_collection.last_create_kwargs['description'] == 'managed-by: cis | cluster: cluster-1'


def test_wideip_create_without_identifiers_has_no_description_stamp():
    """WideIP description is omitted when both cluster and UID are absent."""
    wideip_collection = _DummyWideIPCollection()
    manager = GTMWideIP(
        _DummyGTMWideIP(wideip_collection),
        'Common',
        local_cluster_name=None,
        cluster_digital_asset_id=None)

    config = {
        'name': 'app.example.com',
        'LoadBalancingMode': 'round-robin',
    }

    manager.create_wideip(config, {})

    assert 'description' not in wideip_collection.last_create_kwargs


# --- Enhancement 6: Zone-based disablement ---

def test_pre_process_gtm_zone_disablement_filters_members():
    """Disabled zones remove matching members from pool and rebuild members list."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {
                            'name': 'pool1',
                            'fallbackMode': 'none',
                            'LoadBalancingMode': 'round-robin',
                            'members': [
                                '10.1.0.1|10.2.0.3|80',
                                '10.1.0.2|10.3.0.4|80',
                            ],
                            'member-info': [
                                {
                                    'data-server': '10.1.0.1',
                                    'pool-member-address': '10.2.0.3',
                                    'pool-member-port': '80',
                                    'availability-zone': 'us-east-1a',
                                },
                                {
                                    'data-server': '10.1.0.2',
                                    'pool-member-address': '10.3.0.4',
                                    'pool-member-port': '80',
                                    'availability-zone': 'us-east-1b',
                                },
                            ],
                        }
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config, disabled_availability_zones=['us-east-1a'])
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert len(pool['member-info']) == 1
    assert pool['member-info'][0]['availability-zone'] == 'us-east-1b'
    assert pool['members'] == ['10.1.0.2|10.3.0.4|80']


def test_pre_process_gtm_no_disabled_zones_keeps_all_members():
    """When no zones are disabled all members are preserved."""
    config = {
        'Common': {
            'wideIPs': [
                {
                    'name': 'app.example.com',
                    'LoadBalancingMode': 'round-robin',
                    'pools': [
                        {
                            'name': 'pool1',
                            'fallbackMode': 'none',
                            'LoadBalancingMode': 'round-robin',
                            'members': ['10.1.0.1|10.2.0.3|80'],
                            'member-info': [
                                {
                                    'data-server': '10.1.0.1',
                                    'pool-member-address': '10.2.0.3',
                                    'pool-member-port': '80',
                                    'availability-zone': 'us-east-1a',
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    }
    GTMUtils.pre_process_gtm(config, disabled_availability_zones=[])
    pool = config['Common']['wideIPs'][0]['pools'][0]
    assert len(pool['member-info']) == 1
    assert len(pool['members']) == 1


# --- global config: cluster-digital-asset-id extraction ---

def test_handle_global_config_with_digital_asset_id(request):
    """cluster-digital-asset-id in global config is extracted and returned."""
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())
        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {
            'global': {
                'log-level': 'INFO',
                'verify-interval': 30,
                'local-cluster-name': 'cluster-west-1',
                'cluster-digital-asset-id': 'bdee68ed-3157-44a7-a404-f3c311f5b0c3',
            }
        }
        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, vx_p, local_cluster_name, cluster_digital_asset_id = \
            bigipconfigdriver._handle_global_config(r)
        assert verify_interval == 30
        assert local_cluster_name == 'cluster-west-1'
        assert cluster_digital_asset_id == 'bdee68ed-3157-44a7-a404-f3c311f5b0c3'
        assert vx_p is None
    finally:
        assert handler is not None
        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


# --- get_gtm_config: disabledAvailabilityZones passthrough ---

def test_get_gtm_config_returns_disabled_zones():
    """get_gtm_config passes disabledAvailabilityZones through from the gtm section."""
    config = {
        'gtm': {
            'config': {'Common': {'wideIPs': []}},
            'deletedTenants': [],
            'activeTenants': [],
            'disabledAvailabilityZones': ['us-east-1a', 'us-west-2b'],
        }
    }
    result = bigipconfigdriver.get_gtm_config(config)
    assert result.get('disabledAvailabilityZones') == ['us-east-1a', 'us-west-2b']


def test_get_gtm_config_no_disabled_zones_returns_empty():
    """get_gtm_config returns empty list when disabledAvailabilityZones absent."""
    config = {
        'gtm': {
            'config': {'Common': {'wideIPs': []}},
            'deletedTenants': [],
            'activeTenants': [],
        }
    }
    result = bigipconfigdriver.get_gtm_config(config)
    assert result.get('disabledAvailabilityZones', []) == []


def test_update_gtm_separates_cluster_identifier_and_digital_asset_id():
    """clusterIdentifier updates cluster name while digitalAssetID updates UID field."""

    class _DummyComponent(object):
        def __init__(self):
            self._local_cluster_name = 'old-cluster'
            self._cluster_digital_asset_id = 'old-uid'
            self._enable_data_server_monitor = False

    class _DummyGTMState(object):
        def __init__(self):
            self._pending_cleanup = None
            self._local_cluster_name = 'old-cluster'
            self._cluster_digital_asset_id = 'old-uid'
            self._infrastructure = _DummyComponent()
            self._wideip = _DummyComponent()
            self._pool = _DummyComponent()

        def get_gtm_config(self):
            return {}

    class _DummyManager(object):
        def __init__(self):
            self._gtm = _DummyGTMState()

        def is_gtm(self):
            return True

    handler = bigipconfigdriver.ConfigHandler.__new__(bigipconfigdriver.ConfigHandler)
    mgr = _DummyManager()
    handler._managers = [mgr]

    config = {
        'gtm': {
            'config': {},
            'deletedTenants': [],
            'clusterIdentifier': 'cluster-1',
            'digitalAssetID': 'uid-1',
        }
    }

    incomplete = handler._update_gtm(config)

    assert incomplete == 0
    assert mgr._gtm._local_cluster_name == 'cluster-1'
    assert mgr._gtm._cluster_digital_asset_id == 'uid-1'
    assert mgr._gtm._infrastructure._local_cluster_name == 'cluster-1'
    assert mgr._gtm._infrastructure._cluster_digital_asset_id == 'uid-1'
    assert mgr._gtm._wideip._local_cluster_name == 'cluster-1'
    assert mgr._gtm._wideip._cluster_digital_asset_id == 'uid-1'
    assert mgr._gtm._pool._local_cluster_name == 'cluster-1'
    assert mgr._gtm._pool._cluster_digital_asset_id == 'uid-1'


def test_update_gtm_cluster_identifier_only_keeps_existing_digital_asset_id():
    """When digitalAssetID is absent, existing UID remains unchanged."""

    class _DummyComponent(object):
        def __init__(self):
            self._local_cluster_name = 'old-cluster'
            self._cluster_digital_asset_id = 'existing-uid'
            self._enable_data_server_monitor = False

    class _DummyGTMState(object):
        def __init__(self):
            self._pending_cleanup = None
            self._local_cluster_name = 'old-cluster'
            self._cluster_digital_asset_id = 'existing-uid'
            self._infrastructure = _DummyComponent()
            self._wideip = _DummyComponent()
            self._pool = _DummyComponent()

        def get_gtm_config(self):
            return {}

    class _DummyManager(object):
        def __init__(self):
            self._gtm = _DummyGTMState()

        def is_gtm(self):
            return True

    handler = bigipconfigdriver.ConfigHandler.__new__(bigipconfigdriver.ConfigHandler)
    mgr = _DummyManager()
    handler._managers = [mgr]

    config = {
        'gtm': {
            'config': {},
            'deletedTenants': [],
            'clusterIdentifier': 'cluster-1',
        }
    }

    incomplete = handler._update_gtm(config)

    assert incomplete == 0
    assert mgr._gtm._local_cluster_name == 'cluster-1'
    assert mgr._gtm._cluster_digital_asset_id == 'existing-uid'
    assert mgr._gtm._infrastructure._local_cluster_name == 'cluster-1'
    assert mgr._gtm._infrastructure._cluster_digital_asset_id == 'existing-uid'
    assert mgr._gtm._wideip._local_cluster_name == 'cluster-1'
    assert mgr._gtm._wideip._cluster_digital_asset_id == 'existing-uid'
    assert mgr._gtm._pool._local_cluster_name == 'cluster-1'
    assert mgr._gtm._pool._cluster_digital_asset_id == 'existing-uid'
