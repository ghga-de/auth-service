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

"""Port for the core user registry."""

from abc import ABC, abstractmethod
from typing import Any, Optional, Union

from ..models.ivas import Iva, IvaBasicData, IvaData, IvaState
from ..models.users import User, UserBasicData, UserModifiableData, UserRegisteredData


class UserRegistryPort(ABC):
    """Port providing a registry for users and IVAs."""

    class UserRegistryError(RuntimeError):
        """Base class for user registry errors."""

    class UserCreationError(UserRegistryError):
        """Raised when a user cannot be created in the database."""

        def __init__(self, *, ext_id: str, details: Optional[str] = None):
            message = f"Could not create user with external ID {ext_id}"
            if details:
                message += f": {details}"
            super().__init__(message)

    class UserAlreadyExistsError(UserCreationError):
        """Raised when trying to create a that already exists."""

        def __init__(self, *, ext_id: str):
            super().__init__(ext_id=ext_id, details="user already exists")

    class UserRetrievalError(UserRegistryError):
        """Raised when a user cannot be retrieved from the database."""

        def __init__(self, *, user_id: str):
            message = f"Could not retrieve user with ID {user_id}"
            super().__init__(message)

    class UserDoesNotExistError(UserRegistryError):
        """Raised when trying to access a non-existing user."""

        def __init__(self, *, user_id: str):
            message = f"User with ID {user_id} does not exist"
            super().__init__(message)

    class UserUpdateError(UserRegistryError):
        """Raised when a user cannot be updated in the database."""

        def __init__(self, *, user_id: str):
            message = f"Could not update user with ID {user_id}"
            super().__init__(message)

    class UserDeletionError(UserRegistryError):
        """Raised when a user cannot be deleted in the database."""

        def __init__(self, *, user_id: str):
            message = f"Could not delete user with ID {user_id}"
            super().__init__(message)

    class UserRegistryIvaError(UserRegistryError):
        """Base class for IVA-related user registry errors."""

    class IvaCreationError(UserRegistryIvaError):
        """Raised when an IVA cannot be created in the database."""

        def __init__(self, *, user_id: str):
            message = f"Could not create IVA for user with ID {user_id}"
            super().__init__(message)

    class IvaRetrievalError(UserRegistryIvaError):
        """Raised when IVAs cannot be retrieved from the database."""

        def __init__(
            self, *, iva_id: Optional[str] = None, user_id: Optional[str] = None
        ):
            message = "Could not retrieve IVA"
            if iva_id:
                message += f" with ID {iva_id}"
            if user_id:
                message += f" for user with ID {user_id}"
            super().__init__(message)

    class IvaDoesNotExistError(UserRegistryIvaError):
        """Raised when trying to access a non-existing IVA."""

        def __init__(self, *, iva_id: str, user_id: Optional[str] = None):
            message = (
                f"User with ID {user_id} does not have an IVA with ID {iva_id}"
                if user_id
                else f"IVA with ID {iva_id} does not exist"
            )
            super().__init__(message)

    class IvaModificationError(UserRegistryIvaError):
        """Raised when IVAs cannot be modified in the database."""

        def __init__(self, *, iva_id: str):
            message = f"Could not modify IVA with ID {iva_id}"
            super().__init__(message)

    class IvaDeletionError(UserRegistryIvaError):
        """Raised when IVAs cannot be deleted from the database."""

        def __init__(self, *, iva_id: str):
            message = f"Could not delete IVA with ID {iva_id}"
            super().__init__(message)

    class IvaUnexpectedStateError(UserRegistryIvaError):
        """Raised when an IVA is in an unexpected state."""

        def __init__(self, *, iva_id: str, state: IvaState):
            message = f"IVA with ID {iva_id} has an unexpected state {state.name}"
            super().__init__(message)

    class IvaTooManyVerificationAttemptsError(UserRegistryIvaError):
        """Raised when a verification code if verified too often."""

        def __init__(self, *, iva_id: str):
            message = f"Too many verification attempts for IVA with ID {iva_id}"
            super().__init__(message)

    @staticmethod
    @abstractmethod
    def is_internal_user_id(id_: str) -> bool:
        """Check if the passed ID is an internal user id."""
        ...

    @staticmethod
    @abstractmethod
    def is_external_user_id(id_: str) -> bool:
        """Check if the passed ID is an external user id."""
        ...

    @abstractmethod
    async def create_user(
        self,
        user_data: UserRegisteredData,
    ) -> User:
        """Create a user with the given registration data.

        May raise a UserAlreadyExistsError or a UserCreationError.
        """
        ...

    @abstractmethod
    async def get_user(self, user_id: str) -> User:
        """Get user data.

        May raise a UserDoesNotExistError or a UserRetrievalError.
        """
        ...

    @abstractmethod
    async def update_user(
        self,
        user_id: str,
        user_data: Union[UserBasicData, UserModifiableData],
        *,
        changed_by: Optional[str] = None,
        context: Optional[str] = None,
    ) -> None:
        """Update user data.

        Status change is allowed and recorded with the specified context.

        May raise UserDoesNotExistError or a UserUpdateError.
        """
        ...

    @abstractmethod
    async def delete_user(self, user_id: str) -> None:
        """Delete a user.

        May raise a UserDoesNotExistError or a UserDeletionError.
        """
        ...

    @abstractmethod
    async def create_iva(self, user_id: str, data: IvaBasicData) -> str:
        """Create an IVA for the given user with the given basic data.

        Returns the internal ID of the newly createdIVA.

        May raise a UserDoesNotExistError or an IvaCreationError.
        """
        ...

    @abstractmethod
    async def get_iva(self, iva_id: str) -> Iva:
        """Get the IVA with the given ID.

        May raise a UserRegistryIvaError, which can be an IvaDoesNotExistError,
        orr an IvaRetrievalError.
        """
        ...

    @abstractmethod
    async def get_ivas(self, user_id: str) -> list[IvaData]:
        """Get all IVAs of a user.

        The internal data of the IVAs is not included in the result.

        May raise an IvaRetrievalError.
        """
        ...

    @abstractmethod
    async def update_iva(self, iva: Iva, **update: Any) -> None:
        """Update the IVA with the given data.

        May raise a UserRegistryIvaError, which can be an IvaDoesNotExistError
        or an IvaModificationError.
        """
        ...

    @abstractmethod
    async def delete_iva(self, iva_id: str, *, user_id: Optional[str] = None) -> None:
        """Delete the IVA with the ID.

        If the user ID is given, the IVA is only deleted if it belongs to the user.

        May raise an IvaDoesNotExistError or an IvaDeletionError.
        """
        ...

    @abstractmethod
    async def unverify_iva(self, iva_id: str):
        """Reset an IVA as being unverified.

        May raise a UserRegistryIvaError, which can be an IvaDoesNotExistError,
        an IvaRetrievalError or an IvaModificationError.
        """
        ...

    @abstractmethod
    async def request_iva_verification_code(self, iva_id: str):
        """Request a verification code for the IVA with the given ID.

        May raise a UserRegistryIvaError, which can be an IvaDoesNotExistError,
        an IvaRetrievalError, an IvaUnexpectedStateError or an IvaModificationError.
        """
        ...

    @abstractmethod
    async def create_iva_verification_code(self, iva_id: str) -> str:
        """Create a verification code for the IVA with the given ID.

        The code is returned as a string and its hash is stored in the database.

        May raise a UserRegistryIvaError, which can be an IvaDoesNotExistError,
        an IvaRetrievalError, an IvaUnexpectedStateError or an IvaModificationError.
        """
        ...

    @abstractmethod
    async def confirm_iva_code_transmission(self, iva_id: str) -> None:
        """Confirm the transmission of the verification code for the given IVA.

        May raise a UserRegistryIvaError, which can be an IvaDoesNotExistError,
        an IvaRetrievalError, an IvaUnexpectedStateError or an IvaModificationError.
        """
        ...

    @abstractmethod
    async def validate_iva_verification_code(self, iva_id: str, code: str) -> bool:
        """Validate a verification code for the given IVA.

        Checks whether the given verification code matches the stored hash.

        May raise a UserRegistryIvaError, which can be an IvaDoesNotExistError,
        an IvaIvaRetrievalError, an IvaUnexpectedStateError,
        an IvaTooManyVerificationAttemptsError or an IvaModificationError.
        """
        ...
