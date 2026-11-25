"""
.. module: security_monkey.common.change_record
    :platform: Unix
    :synopsis: Pure helpers for configuration change tracking: computing
    diffs between two configurations, attributing a change to an operator,
    reconstructing historical state from a change timeline, and enforcing
    the change-history retention policy.

    This module intentionally has no Flask/SQLAlchemy dependencies so the change
    tracking logic can be unit tested in isolation and reused by both the
    classic watcher path (datastore.Datastore.store) and the batched
    CloudAux path (datastore_utils.persist_item).

.. version:: $$VERSION$$
"""
import datetime

#: Default number of days of change history that must be queryable.
DEFAULT_RETENTION_DAYS = 90

#: Hard floor for retention. Purge operations must never delete change
#: records newer than this, regardless of the requested retention.
MIN_RETENTION_DAYS = 90

#: Change types recorded in the itemrevisiondiff table.
CHANGE_CREATED = 'created'
CHANGE_UPDATED = 'updated'
CHANGE_DELETED = 'deleted'

#: How far back (in seconds) from the recorded change we look for a
#: correlating CloudTrail event when attributing a change to an operator.
ATTRIBUTION_WINDOW_SECONDS = 15 * 60

#: Actor sources.
ACTOR_SOURCE_CLOUDTRAIL = 'cloudtrail'
ACTOR_SOURCE_WATCHER = 'watcher'
ACTOR_SOURCE_UNKNOWN = 'unknown'


def compute_config_diff(old_config, new_config):
    """
    Compute a structured diff between two configuration dicts.

    :param old_config: The previous configuration (dict or None).
    :param new_config: The new configuration (dict or None).
    :return: dict of the form::

        {
            "added":   {"path.to.key": new_value, ...},
            "removed": {"path.to.key": old_value, ...},
            "changed": {"path.to.key": {"old": old_value, "new": new_value}, ...}
        }

    Paths are dot-joined dictionary keys. List and scalar values are
    compared as a whole. The diff is complete: applying it to ``old_config``
    yields ``new_config``, so before/after states are always restorable.
    """
    diff = {"added": {}, "removed": {}, "changed": {}}
    _diff_values(old_config or {}, new_config or {}, "", diff)
    return diff


def _diff_values(old, new, prefix, diff):
    if not isinstance(old, dict) or not isinstance(new, dict):
        if old != new:
            diff["changed"][prefix] = {"old": old, "new": new}
        return

    for key in sorted(set(old) | set(new)):
        path = "{}{}".format(prefix + "." if prefix else "", key)
        in_old = key in old
        in_new = key in new
        if in_old and not in_new:
            diff["removed"][path] = old[key]
        elif in_new and not in_old:
            diff["added"][path] = new[key]
        else:
            _diff_values(old[key], new[key], path, diff)


def has_changes(diff):
    """Returns True if a diff produced by compute_config_diff is non-empty."""
    return bool(diff["added"] or diff["removed"] or diff["changed"])


def config_at_time(timeline, when):
    """
    Reconstruct the configuration in effect at a point in time from a
    change timeline.

    :param timeline: iterable of change records, each a mapping (or object)
        with ``date_created``, ``change_type`` and ``new_config``. Records
        for one resource, any order.
    :param when: datetime at which to reconstruct the state.
    :return: The configuration dict in effect at ``when`` -- the
        ``new_config`` of the most recent record at or before ``when`` --
        or None if the resource did not exist yet. A record with
        ``change_type`` of 'deleted' yields None from that point on.
    """
    records = sorted(timeline, key=lambda record: _record_get(record, "date_created"))
    state = None
    for record in records:
        if _record_get(record, "date_created") > when:
            break
        if _record_get(record, "change_type") == CHANGE_DELETED:
            state = None
        else:
            state = _record_get(record, "new_config")
    return state


def _record_get(record, field):
    if isinstance(record, dict):
        return record.get(field)
    return getattr(record, field)


def actor_from_cloudtrail(entries, changed_at, window_seconds=ATTRIBUTION_WINDOW_SECONDS):
    """
    Pick the CloudTrail entry that most likely caused a change.

    :param entries: iterable of CloudTrail entries (mappings or objects)
        with ``event_time``, ``user_identity_arn`` and ``event_name``.
    :param changed_at: datetime the change was recorded.
    :param window_seconds: only consider events this many seconds before
        ``changed_at`` (events after ``changed_at`` are ignored).
    :return: (actor, event_name, event_time) of the closest preceding
        entry, or (None, None, None) if no entry correlates.
    """
    best = None
    for entry in entries:
        event_time = _record_get(entry, "event_time")
        if event_time is None or event_time > changed_at:
            continue
        if (changed_at - event_time).total_seconds() > window_seconds:
            continue
        if best is None or event_time > _record_get(best, "event_time"):
            best = entry

    if best is None:
        return None, None, None

    return (_record_get(best, "user_identity_arn"),
            _record_get(best, "event_name"),
            _record_get(best, "event_time"))


def effective_retention_days(requested_days=None):
    """
    Resolve the retention period to enforce. The result is never below
    MIN_RETENTION_DAYS so that 90 days of history are always preserved.
    """
    if requested_days is None:
        requested_days = DEFAULT_RETENTION_DAYS
    return max(int(requested_days), MIN_RETENTION_DAYS)


def retention_cutoff(requested_days=None, now=None):
    """
    Return the oldest datetime that must be kept for the given retention
    request. Records at or after the cutoff must not be purged.
    """
    now = now or datetime.datetime.utcnow()
    return now - datetime.timedelta(days=effective_retention_days(requested_days))
