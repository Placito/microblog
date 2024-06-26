"""Initial migration.

Revision ID: d16b0358e877
Revises: 9e808a3f85ab
Create Date: 2024-04-11 15:10:10.965195

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd16b0358e877'
down_revision = '9e808a3f85ab'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_pic', sa.String(), nullable=True))
        batch_op.drop_column('profile_image')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_image', sa.VARCHAR(length=128), nullable=True))
        batch_op.drop_column('profile_pic')

    # ### end Alembic commands ###
