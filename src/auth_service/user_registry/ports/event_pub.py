# Copyright 2021 - 2025 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""Interface for broadcasting events to other services."""

from abc import ABC, abstractmethod

from ..models.ivas import Iva


class EventPublisherPort(ABC):
    """An interface for an adapter that publishes events happening to this service."""

    @abstractmethod
    async def publish_2fa_recreated(self, *, user_id: str) -> None:
        """Publish an event relaying that the 2nd factor of a user was recreated."""

    @abstractmethod
    async def publish_iva_state_changed(self, *, iva: Iva) -> None:
        """Publish an event relaying that the state of a user IVA has been changed."""

    @abstractmethod
    async def publish_ivas_reset(self, *, user_id: str) -> None:
        """Publish an event relaying that all IVAs of the user have been reset."""
