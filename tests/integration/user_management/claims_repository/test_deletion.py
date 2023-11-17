# Copyright 2021 - 2023 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
# for the German Human Genome-Phenome Archive (GHGA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Test deletion of claims."""

import logging
from datetime import timedelta

from ghga_service_commons.utils.utc_dates import now_as_utc
from hexkit.providers.akafka.testutils import KafkaFixture, kafka_fixture  # noqa: F401
from pytest import LogCaptureFixture, mark

from auth_service.__main__ import prepare_event_subscriber
from auth_service.config import CONFIG

from .fixtures import MongoDbContainer, fixture_mongodb  # noqa: F401


@mark.asyncio
async def test_deletion_handler(
    kafka_fixture: KafkaFixture,  # noqa: F811
    mongodb: MongoDbContainer,
    caplog: LogCaptureFixture,
):
    """Test the dataset deletion handler"""
    config = CONFIG.model_copy(update={"kafka_servers": kafka_fixture.kafka_servers})

    caplog.set_level(logging.INFO)
    records = caplog.records

    db = mongodb.get_connection_client()[config.db_name]
    collection = db.get_collection(config.claims_collection)

    creation_date = now_as_utc()
    claim = {
        "visa_type": "ControlledAccessGrants",
        "visa_value": "https://ghga.de/datasets/some-dataset-id",
        "assertion_date": creation_date,
        "valid_from": creation_date,
        "valid_until": creation_date + timedelta(1),
        "source": "https://ghga.de",
        "sub_source": None,
        "asserted_by": "dac",
        "conditions": None,
        "user_id": "some-user-id",
        "creation_date": creation_date,
        "revocation_date": None,
    }
    collection.insert_one(claim)
    assert collection.find_one({"user_id": "some-user-id"})

    event_type = config.dataset_deletion_event_type
    event_topic = config.dataset_deletion_event_topic
    payload = {"accession": "some-dataset-id"}

    async with prepare_event_subscriber(config=config) as event_subscriber:
        caplog.clear()
        await kafka_fixture.publish_event(
            payload=payload, type_=event_type, topic=event_topic
        )
        await event_subscriber.run(forever=False)
        assert len(records) == 2, records
        messages = [record.message for record in records]
        assert messages[0].startswith('Consuming event of type "dataset_deleted"')
        assert messages[1] == "Deleted 1 claims for dataset some-dataset-id"
        assert not collection.find_one({"user_id": "some-user-id"})

        caplog.clear()
        await kafka_fixture.publish_event(
            payload=payload, type_=event_type, topic=event_topic
        )
        await event_subscriber.run(forever=False)
        assert len(records) == 2, records
        messages = [record.message for record in records]
        assert messages[0].startswith('Consuming event of type "dataset_deleted"')
        assert messages[1] == "Deleted 0 claims for dataset some-dataset-id"
