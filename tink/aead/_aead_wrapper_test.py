# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for tink.python.tink.aead_wrapper."""

from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import _keyset_handle
from tink import _monitoring
from tink import aead
from tink import core
from tink.testing import keyset_builder


AEAD_TEMPLATE = aead.aead_key_templates.AES128_EAX
RAW_AEAD_TEMPLATE = keyset_builder.raw_template(AEAD_TEMPLATE)


def setUpModule():
  aead.register()


class AeadWrapperTest(parameterized.TestCase):

  @parameterized.parameters([AEAD_TEMPLATE, RAW_AEAD_TEMPLATE])
  def test_encrypt_decrypt(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        primitive.decrypt(ciphertext, b'associated_data'), b'plaintext'
    )

  @parameterized.parameters([AEAD_TEMPLATE, RAW_AEAD_TEMPLATE])
  def test_decrypt_unknown_ciphertext_fails(self, template):
    unknown_handle = tink.new_keyset_handle(template)
    unknown_primitive = unknown_handle.primitive(aead.Aead)
    unknown_ciphertext = unknown_primitive.encrypt(
        b'plaintext', b'associated_data'
    )

    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)

    with self.assertRaises(tink.TinkError):
      primitive.decrypt(unknown_ciphertext, b'associated_data')

  @parameterized.parameters([AEAD_TEMPLATE, RAW_AEAD_TEMPLATE])
  def test_decrypt_wrong_associated_data_fails(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)

    ciphertext = primitive.encrypt(b'plaintext', b'associated_data')
    with self.assertRaises(tink.TinkError):
      primitive.decrypt(ciphertext, b'wrong_associated_data')

  @parameterized.parameters([
      (AEAD_TEMPLATE, AEAD_TEMPLATE),
      (RAW_AEAD_TEMPLATE, AEAD_TEMPLATE),
      (AEAD_TEMPLATE, RAW_AEAD_TEMPLATE),
      (RAW_AEAD_TEMPLATE, RAW_AEAD_TEMPLATE),
  ])
  def test_encrypt_decrypt_with_key_rotation(self, template1, template2):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(template1)
    builder.set_primary_key(older_key_id)
    p1 = builder.keyset_handle().primitive(aead.Aead)

    newer_key_id = builder.add_new_key(template2)
    p2 = builder.keyset_handle().primitive(aead.Aead)

    builder.set_primary_key(newer_key_id)
    p3 = builder.keyset_handle().primitive(aead.Aead)

    builder.disable_key(older_key_id)
    p4 = builder.keyset_handle().primitive(aead.Aead)

    self.assertNotEqual(older_key_id, newer_key_id)
    # p1 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext1 = p1.encrypt(b'plaintext', b'ad')
    self.assertEqual(p1.decrypt(ciphertext1, b'ad'), b'plaintext')
    self.assertEqual(p2.decrypt(ciphertext1, b'ad'), b'plaintext')
    self.assertEqual(p3.decrypt(ciphertext1, b'ad'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = p4.decrypt(ciphertext1, b'ad')

    # p2 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext2 = p2.encrypt(b'plaintext', b'ad')
    self.assertEqual(p1.decrypt(ciphertext2, b'ad'), b'plaintext')
    self.assertEqual(p2.decrypt(ciphertext2, b'ad'), b'plaintext')
    self.assertEqual(p3.decrypt(ciphertext2, b'ad'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = p4.decrypt(ciphertext2, b'ad')

    # p3 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext3 = p3.encrypt(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = p1.decrypt(ciphertext3, b'ad')
    self.assertEqual(p2.decrypt(ciphertext3, b'ad'), b'plaintext')
    self.assertEqual(p3.decrypt(ciphertext3, b'ad'), b'plaintext')
    self.assertEqual(p4.decrypt(ciphertext3, b'ad'), b'plaintext')

    # p4 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext4 = p4.encrypt(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = p1.decrypt(ciphertext4, b'ad')
    self.assertEqual(p2.decrypt(ciphertext4, b'ad'), b'plaintext')
    self.assertEqual(p3.decrypt(ciphertext4, b'ad'), b'plaintext')
    self.assertEqual(p4.decrypt(ciphertext4, b'ad'), b'plaintext')


class KeyUsageMonitorTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.key_usage_monitor = mock.MagicMock()
    _monitoring.register_key_usage_monitor_factory(
        lambda annotations: self.key_usage_monitor
    )

  def test_key_usage_monitor_log(self):
    keyset_handle = _keyset_handle._new_keyset_handle_with_annotations(
        AEAD_TEMPLATE, {'test': 'test'}
    )
    primitive = keyset_handle.primitive(aead.Aead)

    ciphertext = primitive.encrypt(b'plaintext', b'associated_data')
    primitive.decrypt(ciphertext, b'associated_data')

    self.assertEqual(self.key_usage_monitor.log.call_count, 2)
    self.key_usage_monitor.log.assert_has_calls([
        mock.call(
            keyset_handle.keyset_info().key_info[0].key_id, len(b'plaintext')
        ),
        mock.call(
            keyset_handle.keyset_info().key_info[0].key_id,
            len(ciphertext) - core.crypto_format.NON_RAW_PREFIX_SIZE,
        ),
    ])

  def test_key_usage_monitor_log_failure(self):
    keyset_handle = _keyset_handle._new_keyset_handle_with_annotations(
        AEAD_TEMPLATE, {'test': 'test'}
    )
    primitive = keyset_handle.primitive(aead.Aead)

    try:
      primitive.decrypt(b'x', b'context')
    except core.TinkError:
      pass

    self.key_usage_monitor.log_failure.assert_called_once()


if __name__ == '__main__':
  absltest.main()
