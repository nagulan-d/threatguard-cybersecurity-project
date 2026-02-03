"""Add website monitoring and subscription support

Revision ID: add_website_monitoring
Revises: b12db61fc188
Create Date: 2025-11-25 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_website_monitoring'
down_revision = 'b12db61fc188'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to User table
    op.add_column('user', sa.Column('subscription', sa.String(20), nullable=True))
    op.add_column('user', sa.Column('created_at', sa.DateTime(), nullable=True))
    
    # Set default values
    op.execute("UPDATE user SET subscription = 'free' WHERE subscription IS NULL")
    op.execute("UPDATE user SET created_at = datetime('now') WHERE created_at IS NULL")
    
    # Create MonitoredWebsite table
    op.create_table('monitored_website',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('url', sa.String(500), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_checked', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create WebsiteAlert table
    op.create_table('website_alert',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('website_id', sa.Integer(), nullable=False),
        sa.Column('threat_level', sa.String(20), nullable=True),
        sa.Column('threat_details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('is_read', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.ForeignKeyConstraint(['website_id'], ['monitored_website.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('website_alert')
    op.drop_table('monitored_website')
    op.drop_column('user', 'created_at')
    op.drop_column('user', 'subscription')
