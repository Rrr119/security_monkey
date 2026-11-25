#     Copyright 2014 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.tests.core.test_change_record
    :platform: Unix
    :synopsis: Acceptance tests for configuration change tracking: diff
    recording and attribution, per-resource time-series queries, auditor
    compatibility, and the 90 day retention guarantee.

.. version:: $$VERSION$$
"""
import datetime
import json

from security_monkey import db
from security_monkey.common.change_record import (
    CHANGE_CREATED,
    CHANGE_UPDATED,
    CHANGE_DELETED,
    ACTOR_SOURCE_CLOUDTRAIL,
    ACTOR_SOURCE_WATCHER,
    MIN_RETENTION_DAYS,
    compute_config_diff,
    config_at_time,
    effective_retention_days,
)
from security_monkey.datastore import (
    Account,
    AccountType,
    CloudTrailEntry,
    Datastore,
    ItemAudit,
    ItemRevisionDiff,
    delete_old_change_records,
)
from security_monkey.tests import SecurityMonkeyTestCase


class MockWatcher:
    """Minimal stand-in for a watcher so store() can attribute changes."""
    index = 'mockwatcher'
    honor_ephemerals = False
    ephemeral_paths = []


IAMROLE_CONFIGS = [
    {
        "name": "app-role",
        "policy": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
        "Arn": "arn:aws:iam::012345678910:role/app-role"
    },
    {
        "name": "app-role",
        "policy": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        "Arn": "arn:aws:iam::012345678910:role/app-role"
    },
    {
        "name": "app-role",
        "policy": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        "Arn": "arn:aws:iam::012345678910:role/app-role",
        "tags": {"owner": "team-a"}
    },
]

SECURITYGROUP_CONFIGS = [
    {
        "name": "web-sg",
        "rules": [{"cidr": "10.0.0.0/8", "port": 443}],
        "Arn": "arn:aws:ec2:us-east-1:012345678910:security-group/sg-1"
    },
    {
        "name": "web-sg",
        "rules": [{"cidr": "0.0.0.0/0", "port": 443}],
        "Arn": "arn:aws:ec2:us-east-1:012345678910:security-group/sg-1"
    },
    {
        "name": "web-sg",
        "rules": [{"cidr": "0.0.0.0/0", "port": 443}, {"cidr": "0.0.0.0/0", "port": 22}],
        "Arn": "arn:aws:ec2:us-east-1:012345678910:security-group/sg-1"
    },
]

S3_CONFIGS = [
    {
        "name": "logs-bucket",
        "Grants": {"alice": ["READ"]},
        "Arn": "arn:aws:s3:::logs-bucket"
    },
    {
        "name": "logs-bucket",
        "Grants": {"alice": ["READ"], "bob": ["WRITE"]},
        "Arn": "arn:aws:s3:::logs-bucket"
    },
    {
        "name": "logs-bucket",
        "Grants": {"bob": ["WRITE"]},
        "Arn": "arn:aws:s3:::logs-bucket"
    },
]

RESOURCE_TYPES = {
    'iamrole': ('universal', IAMROLE_CONFIGS),
    'securitygroup': ('us-east-1', SECURITYGROUP_CONFIGS),
    's3': ('us-east-1', S3_CONFIGS),
}


class ChangeRecordTestCase(SecurityMonkeyTestCase):
    def pre_test_setup(self):
        account_type = AccountType(name='AWS')
        db.session.add(account_type)
        db.session.commit()

        self.account = Account(identifier="012345678910", name="TEST_ACCOUNT",
                               account_type_id=account_type.id, notes="TEST_ACCOUNT",
                               third_party=False, active=True)
        db.session.add(self.account)
        db.session.commit()

        self.datastore = Datastore()
        self.watcher = MockWatcher()

    def _run_change_lifecycle(self, technology, region, configs):
        """Store create -> update -> update -> delete and return the item."""
        name = configs[0]['name']
        item = self.datastore.store(technology, region, self.account.name, name,
                                    True, configs[0], source_watcher=self.watcher)
        self.datastore.store(technology, region, self.account.name, name,
                             True, configs[1], source_watcher=self.watcher)
        self.datastore.store(technology, region, self.account.name, name,
                             True, configs[2], source_watcher=self.watcher)
        self.datastore.store(technology, region, self.account.name, name,
                             False, configs[2], source_watcher=self.watcher)
        return item

    def test_three_resource_types_restore_states_and_operator(self):
        """
        Acceptance: for 3 resource types, every change record restores the
        exact before/after state and carries operator attribution.
        """
        for technology, (region, configs) in RESOURCE_TYPES.items():
            item = self._run_change_lifecycle(technology, region, configs)

            records = self.datastore.get_change_history(item_id=item.id, days=90)
            assert len(records) == 4, "expected 4 change records for {}, got {}".format(
                technology, len(records))

            # Change types and ordering:
            assert [r.change_type for r in records] == [
                CHANGE_CREATED, CHANGE_UPDATED, CHANGE_UPDATED, CHANGE_DELETED]
            assert all(records[i].date_created <= records[i + 1].date_created
                       for i in range(len(records) - 1))

            # Before/after states are fully restorable from each record:
            expected_states = [configs[0], configs[1], configs[2], configs[2]]
            for index, record in enumerate(records):
                assert json.dumps(record.new_config, sort_keys=True) == \
                    json.dumps(expected_states[index], sort_keys=True)
                expected_old = expected_states[index - 1] if index > 0 else {}
                assert json.dumps(record.old_config, sort_keys=True) == \
                    json.dumps(expected_old, sort_keys=True)

                # The diff applied to old_config reproduces new_config:
                assert json.dumps(record.diff, sort_keys=True) == json.dumps(
                    compute_config_diff(expected_old, expected_states[index]), sort_keys=True)

                # Operator attribution is always present:
                assert record.actor == "watcher:{}".format(self.watcher.index)
                assert record.actor_source == ACTOR_SOURCE_WATCHER

            # The timeline reconstructs the state in effect at any moment:
            for record in records:
                if record.change_type == CHANGE_DELETED:
                    assert config_at_time(records, record.date_created) is None
                else:
                    assert json.dumps(config_at_time(records, record.date_created), sort_keys=True) == \
                        json.dumps(record.new_config, sort_keys=True)

    def test_diff_contents_pinpoint_changed_fields(self):
        """The recorded diff identifies exactly which fields changed."""
        region, configs = RESOURCE_TYPES['s3']
        self._run_change_lifecycle('s3', region, configs)

        records = self.datastore.get_change_history(ctype='s3', name='logs-bucket', days=90)
        assert len(records) == 4

        # created: everything is "added"
        assert records[0].diff['added']['Grants'] == {"alice": ["READ"]}
        assert records[0].diff['removed'] == {}
        assert records[0].diff['changed'] == {}

        # first update: bob granted WRITE -- pinpointed at the exact key
        assert records[1].diff['added'] == {'Grants.bob': ["WRITE"]}
        assert records[1].diff['removed'] == {}
        assert records[1].diff['changed'] == {}

        # second update: alice's grant removed -- pinpointed at the exact key
        assert records[2].diff['added'] == {}
        assert records[2].diff['removed'] == {'Grants.alice': ["READ"]}
        assert records[2].diff['changed'] == {}

    def test_cloudtrail_attribution_identifies_operator(self):
        """When a CloudTrail event correlates, the record names the operator."""
        region, configs = RESOURCE_TYPES['iamrole']
        item = self.datastore.store('iamrole', region, self.account.name, 'app-role',
                                    True, configs[0], source_watcher=self.watcher)

        operator_arn = 'arn:aws:iam::012345678910:user/alice'
        entry = CloudTrailEntry(
            event_id='00000000-0000-0000-0000-000000000001',
            event_source='iam.amazonaws.com',
            event_name='UpdateRole',
            event_time=datetime.datetime.utcnow(),
            user_identity_arn=operator_arn,
            revision_id=item.latest_revision_id,
            item_id=item.id)
        db.session.add(entry)
        db.session.commit()

        self.datastore.store('iamrole', region, self.account.name, 'app-role',
                             True, configs[1], source_watcher=self.watcher)

        records = self.datastore.get_change_history(item_id=item.id, days=90)
        assert len(records) == 2
        assert records[1].actor == operator_arn
        assert records[1].actor_source == ACTOR_SOURCE_CLOUDTRAIL

    def test_ninety_day_history_query_loses_nothing(self):
        """
        Acceptance: querying 90 days of history returns every record in the
        window, and purging never deletes records newer than 90 days.
        """
        region, configs = RESOURCE_TYPES['securitygroup']
        item = self._run_change_lifecycle('securitygroup', region, configs)

        records = self.datastore.get_change_history(item_id=item.id, days=90)
        assert len(records) == 4

        # Spread the records across time: 89, 60, 30 and 1 days old.
        ages = [89, 60, 30, 1]
        now = datetime.datetime.utcnow()
        for record, age in zip(records, ages):
            record.date_created = now - datetime.timedelta(days=age)
            db.session.add(record)
        db.session.commit()

        # All four records are within 90 days -- the query must return all of them.
        history = self.datastore.get_change_history(item_id=item.id, days=90)
        assert len(history) == 4
        assert [r.id for r in history] == [r.id for r in records]

        # A record older than 90 days is outside the query window.
        old_record = records[0]
        old_record.date_created = now - datetime.timedelta(days=91)
        db.session.add(old_record)
        db.session.commit()
        history = self.datastore.get_change_history(item_id=item.id, days=90)
        assert len(history) == 3

        # Purging with a retention shorter than 90 days must still keep 90 days.
        old_record.date_created = now - datetime.timedelta(days=89)
        db.session.add(old_record)
        db.session.commit()
        deleted = delete_old_change_records(retention_days=30)
        assert deleted == 0
        history = self.datastore.get_change_history(item_id=item.id, days=90)
        assert len(history) == 4, "90 days of history must survive any purge"

        # Records genuinely older than 90 days are the only ones purged.
        old_record.date_created = now - datetime.timedelta(days=120)
        db.session.add(old_record)
        db.session.commit()
        deleted = delete_old_change_records()
        assert deleted == 1
        assert ItemRevisionDiff.query.filter(ItemRevisionDiff.item_id == item.id).count() == 3

        # The retention floor itself is enforced by the policy helper.
        assert effective_retention_days(30) == MIN_RETENTION_DAYS
        assert effective_retention_days(120) == 120

    def test_auditor_flow_unaffected_by_change_tracking(self):
        """
        Auditor compatibility: storing items with audit issues still creates
        and clears ItemAudit rows exactly as before, while also writing
        change records.
        """
        region, configs = RESOURCE_TYPES['iamrole']

        item = self.datastore.store('iamrole', region, self.account.name, 'app-role',
                                    True, configs[0], source_watcher=self.watcher)
        assert len(item.issues) == 0

        issue = ItemAudit(score=10, issue="IAM Role has full admin permissions.",
                          notes=json.dumps(configs[1]), item_id=item.id)

        item = self.datastore.store('iamrole', region, self.account.name, 'app-role',
                                    True, configs[1], new_issues=[issue],
                                    source_watcher=self.watcher)
        assert len(item.issues) == 1
        assert item.issues[0].issue == "IAM Role has full admin permissions."

        # The issue is cleared on the next store without issues, as before:
        item = self.datastore.store('iamrole', region, self.account.name, 'app-role',
                                    True, configs[2], source_watcher=self.watcher)
        assert len(item.issues) == 0

        # ... and every store still produced a change record:
        records = self.datastore.get_change_history(item_id=item.id, days=90)
        assert len(records) == 3
        assert [r.change_type for r in records] == [CHANGE_CREATED, CHANGE_UPDATED, CHANGE_UPDATED]

    def test_ephemeral_updates_do_not_create_change_records(self):
        """Ephemeral (non-durable) updates must not pollute the audit trail."""
        region, configs = RESOURCE_TYPES['s3']
        item = self.datastore.store('s3', region, self.account.name, 'logs-bucket',
                                    True, configs[0], source_watcher=self.watcher)
        self.datastore.store('s3', region, self.account.name, 'logs-bucket',
                             True, configs[1], ephemeral=True, source_watcher=self.watcher)

        records = self.datastore.get_change_history(item_id=item.id, days=90)
        assert len(records) == 1
        assert records[0].change_type == CHANGE_CREATED
