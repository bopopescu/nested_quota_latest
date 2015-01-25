# Copyright 2013 Intel Corporation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy import Integer


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Add a new column metrics to save metrics info for compute nodes
    quotas = Table('quotas', meta, autoload=True)
    shadow_quotas = Table('shadow_quotas', meta, autoload=True)

    allocated = Column('allocated', Integer, default=0)
    shadow_allocated= Column('allocated', Integer, default=0)
    quotas.create_column(allocated)
    shadow_quotas.create_column(shadow_allocated)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Remove the new column
    quotas = Table('quotas', meta, autoload=True)
    shadow_quotas = Table('shadow_quotas', meta, autoload=True)

    quotas.drop_column('allocated')
    shadow_quotas.drop_column('allocated')
