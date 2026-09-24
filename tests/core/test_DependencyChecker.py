# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import sys

import os
from mock import mock, MagicMock

from qrl.core.misc import logger
from qrl.core.misc.DependencyChecker import DependencyChecker

logger.initialize_default()


class TestDependencyChecker(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestDependencyChecker, self).__init__(*args, **kwargs)

    def test_check(self):
        with mock.patch('sys.exit'):
            sys.exit = MagicMock()
            DependencyChecker.check()

    def test_check_fail(self):
        with mock.patch('sys.exit'):
            sys.exit = MagicMock()
            with mock.patch('qrl.core.misc.DependencyChecker.DependencyChecker') as mockDepChecker:
                test_path = os.path.dirname(os.path.abspath(__file__))
                dummy_path = os.path.join(test_path, "..", "data", 'misc', 'dummy_requirements.txt')
                mockDepChecker._get_requirements_path = MagicMock(return_value=dummy_path)

                DependencyChecker.check()
                sys.exit.assert_called()

    def test_pkg_resources_fallback_strips_inline_comments(self):
        requirements = 'protobuf>=4.21.0,<7.0.0  # gRPC\n   # comment\n\n'
        module = 'qrl.core.misc.DependencyChecker'
        with mock.patch(f'{module}.MODERN_PACKAGING', False), \
                mock.patch(f'{module}.pkg_resources') as pkg_resources, \
                mock.patch('builtins.open', mock.mock_open(read_data=requirements)):
            DependencyChecker.check()

        pkg_resources.require.assert_called_once_with(['protobuf>=4.21.0,<7.0.0'])
