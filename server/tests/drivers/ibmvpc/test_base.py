# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import Dict

import tft.artemis.drivers.ibmcloudvpc

IBMVPC_TAGS_EXAMPLES: Dict[str, str] = {
    'tag1': 'value1',
    'tag2': 'value2',
    # TODO: wrong type, but that's on purpose: our code expects `str`, but we already encountered `None` there.
    # We must handle such an invalid value, but in the long term, we need to prevent `None` sneaking in.
    'tag3': None,  # type: ignore[dict-item]
    'tag4': '',
    'tag5': 'foo bar',
    'tag6': 'foo "bar"',
    'tag7': "foo 'bar'",
    'tag8': 'https://foo.bar/~baz',
    # This one is exactly matching the limit...
    'tag9': 'a' * (tft.artemis.drivers.ibmcloudvpc.TAG_MAX_LENGTH - 5),
    # This one is one character beyond the limit...
    'tag10': 'a' * (tft.artemis.drivers.ibmcloudvpc.TAG_MAX_LENGTH - 5),
    # And this one has a name that is way too long.
    'c' * tft.artemis.drivers.ibmcloudvpc.TAG_MAX_LENGTH: 'ddddd',
    # Some real-world usage
    'COLDSTORE_URL': f'http://artifacts.osci.redhat.com//baseos-ci//brew-build/66/53/25/66532507//https___{"f" * 45}-ci-test-brew-ts_tmt-artemis/7663//',  # noqa: E501
}


def test_serialize_tags() -> None:
    assert tft.artemis.drivers.ibmcloudvpc._serialize_tags(IBMVPC_TAGS_EXAMPLES) == [
        'tag1:value1',
        'tag2:value2',
        'tag3',
        'tag4',
        'tag5:foo bar',
        'tag6:foo _bar_',
        'tag7:foo _bar_',
        'tag8:https___foo.bar__baz',
        f'tag9:{"a" * (tft.artemis.drivers.ibmcloudvpc.TAG_MAX_LENGTH - 5)}',
        f'tag10:{"a" * (tft.artemis.drivers.ibmcloudvpc.TAG_MAX_LENGTH - 6)}',
        'c' * tft.artemis.drivers.ibmcloudvpc.TAG_MAX_LENGTH,
        f'COLDSTORE_URL:http___artifacts.osci.redhat.com__baseos-ci__brew-build_66_53_25_66532507__https___{"f" * 31}',
    ]
