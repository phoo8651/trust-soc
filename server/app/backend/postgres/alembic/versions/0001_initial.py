"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2025-11-18 12:40:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(), primary_key=True),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("agent_version", sa.String()),
        sa.Column("registered_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("refresh_token", sa.Text(), nullable=False),
        sa.Column("access_token", sa.Text(), nullable=False),
        sa.Column("access_expires", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "idempotency_keys",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("idem_key", sa.String(), nullable=False),
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("ts_bucket", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("client_id", "agent_id", "idem_key", name="uq_idem_key"),
        sa.UniqueConstraint("client_id", "agent_id", "nonce", "ts_bucket", name="uq_nonce_bucket"),
    )
    op.create_index("idx_idem_created_at", "idempotency_keys", ["created_at"])

    op.create_table(
        "raw_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("source_type", sa.String(), nullable=False),
        sa.Column("raw_line", sa.Text(), nullable=False),
        sa.Column("hash_sha256", sa.String()),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("inserted_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        postgresql_partition_by="RANGE (ts)",
    )
    op.create_index("idx_raw_logs_client_ts", "raw_logs", ["client_id", "ts"])
    op.create_index("idx_raw_logs_hash", "raw_logs", ["hash_sha256"])
    op.create_index("idx_raw_logs_ts_brin", "raw_logs", ["ts"], postgresql_using="brin")

    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("category", sa.String()),
        sa.Column("severity", sa.String()),
        sa.Column("summary", sa.Text()),
        sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rule_id", sa.String()),
        sa.Column("ml_score", sa.Numeric()),
        sa.Column("source_ip_enc", sa.String()),
        sa.Column("url_path", sa.String()),
        sa.Column("ua_hash", sa.String()),
        sa.Column("context", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        postgresql_partition_by="RANGE (ts)",
    )
    op.create_index("idx_events_client_ts", "events", ["client_id", "ts"])
    op.create_index("idx_events_rule", "events", ["rule_id"])
    op.create_index("idx_events_ts_brin", "events", ["ts"], postgresql_using="brin")

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(), primary_key=True),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("time_window", postgresql.TSRANGE()),
        sa.Column("category", sa.String()),
        sa.Column("summary", sa.Text()),
        sa.Column("attack_mapping", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("recommended_actions", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("confidence", sa.Numeric()),
        sa.Column("status", sa.String()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("incident_metadata", postgresql.JSONB(astext_type=sa.Text())),
        postgresql_partition_by="RANGE (created_at)",
    )
    op.create_index("idx_incidents_client_created", "incidents", ["client_id", "created_at"])
    op.create_index("idx_incidents_created_brin", "incidents", ["created_at"], postgresql_using="brin")

    op.create_table(
        "jobs",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("job_type", sa.String(), nullable=False),
        sa.Column("args", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("approvals_required", sa.Integer()),
        sa.Column("approvals_granted", sa.Integer(), server_default=sa.text("0")),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("rate_limit_per_min", sa.Integer()),
        sa.Column("dry_run", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("signature", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("status", sa.String(), server_default=sa.text("'pending'")),
        sa.Column("last_delivered_at", sa.DateTime(timezone=True)),
        sa.Column("command_hash", sa.String()),
        sa.UniqueConstraint("client_id", "agent_id", "idempotency_key", name="uq_job_idempotency"),
    )
    op.create_index("idx_jobs_agent_status", "jobs", ["agent_id", "status"])
    op.create_index("idx_jobs_status_created", "jobs", ["status", "created_at"])

    op.create_table(
        "policies",
        sa.Column("policy_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("client_id", sa.String()),
        sa.Column("host", sa.String()),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("etag", sa.String(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("scope", "client_id", "host", name="uq_policy_scope"),
    )

    op.create_table(
        "audit_logs",
        sa.Column("audit_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("context", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_audit_subject", "audit_logs", ["subject"])
    op.create_index("idx_audit_created", "audit_logs", ["created_at"])

    op.create_table(
        "job_results",
        sa.Column("result_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("success", sa.Boolean()),
        sa.Column("output_snippet", sa.Text()),
        sa.Column("error_detail", sa.Text()),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"]),
    )

    op.create_table(
        "job_approvals",
        sa.Column("approval_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("approver", sa.String(), nullable=False),
        sa.Column("comment", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"]),
        sa.UniqueConstraint("job_id", "approver", name="uq_job_approver"),
    )


def downgrade():
    op.drop_table("job_approvals")
    op.drop_table("job_results")
    op.drop_index("idx_audit_created", table_name="audit_logs")
    op.drop_index("idx_audit_subject", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("policies")
    op.drop_index("idx_jobs_status_created", table_name="jobs")
    op.drop_index("idx_jobs_agent_status", table_name="jobs")
    op.drop_table("jobs")
    op.drop_index("idx_incidents_created_brin", table_name="incidents")
    op.drop_index("idx_incidents_client_created", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("idx_events_ts_brin", table_name="events")
    op.drop_index("idx_events_rule", table_name="events")
    op.drop_index("idx_events_client_ts", table_name="events")
    op.drop_table("events")
    op.drop_index("idx_raw_logs_ts_brin", table_name="raw_logs")
    op.drop_index("idx_raw_logs_hash", table_name="raw_logs")
    op.drop_index("idx_raw_logs_client_ts", table_name="raw_logs")
    op.drop_table("raw_logs")
    op.drop_index("idx_idem_created_at", table_name="idempotency_keys")
    op.drop_table("idempotency_keys")
    op.drop_table("agents")
