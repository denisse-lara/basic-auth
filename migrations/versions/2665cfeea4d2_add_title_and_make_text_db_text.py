"""add title and make text db.Text

Revision ID: 2665cfeea4d2
Revises: 097dd80e3c67
Create Date: 2022-03-08 15:49:52.392140

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2665cfeea4d2'
down_revision = '097dd80e3c67'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('page', sa.Column('title', sa.String(length=50), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('page', 'title')
    # ### end Alembic commands ###
