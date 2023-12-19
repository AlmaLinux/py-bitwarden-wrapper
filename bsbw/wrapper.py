import base64
import json
import logging
import os
import re
import time
import typing

import jmespath
from cryptography.fernet import Fernet
from plumbum import local
from pydantic import BaseModel

from bsbw.errors import *


__all__ = [
    'BWCLIWrapper',
    'CredentialsContainer',
]


ENV_VAR_NAME = 'BW_SESSION'


class BaseCredentials(BaseModel):
    username: typing.Optional[str]
    password: typing.Optional[str]


class NamedCredentials(BaseCredentials):
    name: str


class EncryptedCredentials(BaseCredentials):
    password: typing.Optional[bytes]


class CredentialsContainer:
    __slots__ = ('__creds_dict', '__cypher')

    def __init__(
            self, credentials: typing.Union[
            typing.Dict[str, dict],
            typing.List[typing.Dict[str, str]]]
    ):
        self.__cypher = Fernet(Fernet.generate_key())
        self.__creds_dict = {}
        if isinstance(credentials, dict):
            temp_storage = {
                name: BaseCredentials(**creds).dict()
                for name, creds in credentials.items()
            }
        else:
            validation = [
                NamedCredentials(**item) for item in credentials
            ]
            temp_storage = {
                item.name: item.dict() for item in validation
            }
            del validation
        for name, cred in temp_storage.items():
            if cred.get('password'):
                password = self.__cypher.encrypt(cred['password'].encode('utf-8'))
            else:
                password = None
            self.__creds_dict[name] = EncryptedCredentials(
                username=cred['username'],
                password=password
            )
        del temp_storage

    def __get_credentials(
            self, name: str, password_only: bool = False
    ) -> typing.Union[str, typing.Tuple[str, str]]:
        if name not in self.__creds_dict:
            raise ValueError(f'No credentials named "{name}"')
        creds = self.__creds_dict[name]
        password = creds.password
        if creds.password:
            password = self.__cypher.decrypt(creds.password).decode('utf-8')
        if password_only:
            return password
        return creds.username, password

    def __get(
            self, item: str, exception_class: typing.Type[Exception] = None,
            default=None
    ) -> typing.Optional[typing.Union[str, typing.Tuple[str, str]]]:
        if item not in self.__creds_dict:
            if exception_class:
                raise exception_class(item)
            return default
        return self.__get_credentials(item)

    # Some time you need a more granular control about whether you want
    # user/password pair or just password, hence the function that allows it.
    def get_credentials(
            self, name: str, password_only: bool = False
    ) -> typing.Union[str, typing.Tuple[str, str]]:
        return self.__get_credentials(name, password_only=password_only)

    def get(
            self, item: str, default=None
    ) -> typing.Optional[typing.Union[str, typing.Tuple[str, str]]]:
        return self.__get(item, default=default)

    def __contains__(self, item: str) -> bool:
        return item in self.__creds_dict

    def __dir__(self) -> typing.Iterable[str]:
        return [self.get.__name__, self.get_credentials.__name__]

    def __getattr__(self, item) -> typing.Union[str, typing.Tuple[str, str]]:
        return self.__get(item, exception_class=AttributeError)

    def __getitem__(self, item) -> typing.Union[str, typing.Tuple[str, str]]:
        return self.__get(item, exception_class=KeyError)


class BWCLIWrapper:

    def __init__(
        self,
        username: str,
        password_file: str,
        collection_id: typing.Optional[str] = None,
        verbose: bool = False,
    ):
        log_level = 'DEBUG' if verbose else 'INFO'
        self.__log = logging.getLogger(self.__class__.__name__)
        self.__log.setLevel(log_level)
        self._bw = local['bw']
        # Check that tool is accessible
        try:
            self.get_version()
        except BWCLIError as e:
            self.__log.error(str(e))
            raise e

        self.__username = username
        self.__password_file = base64.urlsafe_b64encode(os.path.expanduser(
            os.path.expandvars(password_file)).encode('utf-8'))
        self.__collection_id = collection_id

    def __dir__(self) -> typing.Iterable[str]:
        return [
            self.get_secrets.__name__, 'session_key',
            self.login.__name__, self.logout.__name__,
            self.bw.__name__, self.bw_simple.__name__,
            self.bw_simple_with_key.__name__,
            self.sync.__name__,
        ]

    def bw(
            self, *args, ignore_errors: bool = False,
    ) -> typing.Tuple[int, str, str]:
        exit_code, stdout, stderr = self._bw.run(args=args, retcode=None)
        if exit_code != 0 and not ignore_errors:
            message = (
                f'Error when executing bw {" ".join(args)}\n'
                f'Stdout: {stdout}\n'
                f'Stderr: {stderr}\n'
            )
            raise BWCLIError(message)
        self.__log.debug('Exit code: %d\nStdout:\n%s\nStderr:\n%s')
        return exit_code, stdout.strip(), stderr.strip()

    def bw_simple(self, *args) -> str:
        _, out, _ = self.bw(*args)
        return out.strip()

    def bw_simple_with_key(self, *args, session_key: str = None) -> str:
        s_key = session_key or self.__get_session_key()
        args += '--session', s_key
        return self.bw_simple(*args)

    def get_version(self) -> str:
        self.__log.debug('Getting bw CLI version')
        return self.bw_simple('--version').strip()

    def get_secrets(self):
        retries = 5
        self.login()
        self.sync()
        self.__log.info('Loading the secrets from Bitwarden')
        args = ['list', 'items']
        if self.__collection_id:
            args.extend(['--collectionid', self.__collection_id])
        out = self.bw_simple_with_key(*args)
        sleep_time = 1
        while not out and retries > 0:
            self.__log.warning('Received empty response from Bitwarden')
            time.sleep(sleep_time)
            retries -= 1
            sleep_time += 1
            out = self.bw_simple_with_key(*args)
        if not out:
            raise BWCLIFetchError('Cannot get secrets from Bitwarden')
        result = json.loads(out)
        reduced_result = [
            {
                key.split('.')[-1]: jmespath.search(key, item)
                for key in ('name', 'login.username', 'login.password')
            } for item in result
        ]
        self.__log.info('Loading completed')
        return CredentialsContainer(reduced_result)

    @property
    def session_key(self) -> typing.Optional[str]:
        return self.__get_session_key()

    def __get_pw_file(self):
        return base64.urlsafe_b64decode(self.__password_file).decode('utf-8')

    def __get_session_key(self) -> str:
        # Check preset variable
        if os.environ.get(ENV_VAR_NAME):
            return os.environ[ENV_VAR_NAME]
        session_key = self.bw_simple(
            'unlock', '--passwordfile', self.__get_pw_file(), '--raw'
        )
        os.environ[ENV_VAR_NAME] = session_key
        return session_key

    def login(self):
        error_message = None
        exception = None
        self.__log.info('Logging into Bitwarden...')
        try:
            self.__log.debug('Check if login already performed')
            code, out, err = self.bw('login', '--check', ignore_errors=True)
            self.__log.debug('Check artifacts: code: %d, out: %s, err: %s',
                             code, out, err)
            if code == 0 and re.search(r'.* logged in!$', out, re.IGNORECASE):
                return

            self.logout()
            self.bw_simple(
                'login', self.__username, '--passwordfile',
                self.__get_pw_file(), '--raw'
            )
        except BWCLIError as e:
            exception = e
            error_message = (f'Cannot login to the Bitwarden due to the problem '
                             f'with "bw" utility, original error message: %s')
        except Exception as e:
            exception = e
            error_message = (f'Unknown error during the login attempt. '
                             f'Original error message: %s')
        finally:
            if error_message and exception:
                self.__log.error(error_message, str(exception))
                raise BWCLILoginError() from exception
            else:
                self.__log.info('Login successful')

    def logout(self):
        acceptable = 'You are not logged in.'
        code, out, err = self.bw('login', '--check', ignore_errors=True)
        if code == 1 and (out == acceptable or err == acceptable):
            return
        code, out, err = self.bw('logout', ignore_errors=True)
        if code != 0:
            if out == acceptable or err == acceptable:
                return
            raise BWCLIError(f'Error during logout: {err}')

    def sync(self):
        self.bw_simple('sync')

    def lock(self):
        self.bw_simple('lock')

    def __enter__(self):
        self.login()
        self.sync()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
