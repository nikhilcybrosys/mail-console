import pytest
from django.db import IntegrityError, connection
from django.db.utils import InternalError, ProgrammingError, DatabaseError

from apps.audit.models import AuditLog
from apps.audit.service import record, verify_chain

pytestmark = pytest.mark.django_db


def test_chain_links_and_verifies():
    a = record("x.one", actor="a@example.com", target="t1", details={"n": 1})
    b = record("x.two", actor="b@example.com", details={"n": 2})
    assert b.prev_hash == a.row_hash
    assert verify_chain() == (True, None)


def test_app_layer_blocks_edit_and_delete():
    row = record("x.one")
    row.action = "changed"
    with pytest.raises(PermissionError):
        row.save()
    with pytest.raises(PermissionError):
        row.delete()


def test_db_trigger_blocks_update_delete_truncate():
    record("x.one")
    with pytest.raises(DatabaseError):
        with connection.cursor() as c, __import__("django").db.transaction.atomic():
            c.execute("UPDATE audit_auditlog SET action='evil'")
    with pytest.raises(DatabaseError):
        with connection.cursor() as c, __import__("django").db.transaction.atomic():
            c.execute("DELETE FROM audit_auditlog")
    with pytest.raises(DatabaseError):
        with connection.cursor() as c, __import__("django").db.transaction.atomic():
            c.execute("TRUNCATE audit_auditlog")
    assert AuditLog.objects.count() == 1


def test_tamper_is_detected_when_trigger_bypassed():
    """A superuser who disables the trigger and edits a row still breaks the hash chain."""
    record("x.one")
    r2 = record("x.two", details={"k": "v"})
    record("x.three")
    with connection.cursor() as c:
        c.execute("ALTER TABLE audit_auditlog DISABLE TRIGGER audit_auditlog_no_update_delete")
        c.execute("UPDATE audit_auditlog SET target='forged' WHERE id=%s", [r2.id])
        c.execute("ALTER TABLE audit_auditlog ENABLE TRIGGER audit_auditlog_no_update_delete")
    ok, bad = verify_chain()
    assert not ok and bad == r2.id
