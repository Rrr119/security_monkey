"""Adding itemrevisiondiff change history table

Revision ID: a1b2c3d4e5f6
Revises: 15e39d43395f
Create Date: 2026-11-26 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '15e39d43395f'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


def upgrade():
    op.create_table(
        'itemrevisiondiff',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('item_id', sa.Integer(), nullable=False),
        sa.Column('revision_id', sa.Integer(), nullable=True),
        sa.Column('previous_revision_id', sa.Integer(), nullable=True),
        sa.Column('change_type', sa.String(length=16), nullable=False),
        sa.Column('diff', postgresql.JSON(), nullable=True),
        sa.Column('old_config', postgresql.JSON(), nullable=True),
        sa.Column('new_config', postgresql.JSON(), nullable=True),
        sa.Column('actor', sa.String(length=512), nullable=True),
        sa.Column('actor_source', sa.String(length=64), nullable=False),
        sa.Column('date_created', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['item_id'], ['item.id'], ),
        sa.ForeignKeyConstraint(['revision_id'], ['itemrevision.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_itemrevisiondiff_item_id', 'itemrevisiondiff', ['item_id'])
    op.create_index('ix_itemrevisiondiff_revision_id', 'itemrevisiondiff', ['revision_id'])
    op.create_index('ix_itemrevisiondiff_change_type', 'itemrevisiondiff', ['change_type'])
    op.create_index('ix_itemrevisiondiff_actor', 'itemrevisiondiff', ['actor'])
    op.create_index('ix_itemrevisiondiff_date_created', 'itemrevisiondiff', ['date_created'])


def downgrade():
    op.drop_index('ix_itemrevisiondiff_date_created', table_name='itemrevisiondiff')
    op.drop_index('ix_itemrevisiondiff_actor', table_name='itemrevisiondiff')
    op.drop_index('ix_itemrevisiondiff_change_type', table_name='itemrevisiondiff')
    op.drop_index('ix_itemrevisiondiff_revision_id', table_name='itemrevisiondiff')
    op.drop_index('ix_itemrevisiondiff_item_id', table_name='itemrevisiondiff')
    op.drop_table('itemrevisiondiff')
