import logging

logger = logging.getLogger(__name__)

UNKNOWN = "Unknown"


class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True

            self._base_url = "http://127.0.0.1/stub/"
            self._gwt_permutation = UNKNOWN
            self._gwt_version = UNKNOWN
            self._rpc_version = UNKNOWN
            self._rpc_flags = UNKNOWN
            self._rpc_mode = False
            self._filter = ""

    def __str__(self):
        str_representation = f'<Config gwt_version="{self._gwt_version}" X-GWT-Module-Base={self._base_url} X-GWT-Permutation={self._gwt_permutation} '

        if self._rpc_mode:
            str_representation += f'rpc_version={self._rpc_version} rpc_flags={self._rpc_flags} '

        str_representation += '/>'
        return str_representation

    @property
    def base_url(self):
        return self._base_url

    @base_url.setter
    def base_url(self, value):
        logger.info(f"Setting base url to {value}")
        self._base_url = value

    @property
    def gwt_permutation(self):
        return self._gwt_permutation

    @gwt_permutation.setter
    def gwt_permutation(self, value):
        if self._gwt_permutation != UNKNOWN:
            return

        logger.info(f"Setting permutation to {value}")
        self._gwt_permutation = value

    @property
    def gwt_version(self):
        return self._gwt_version

    @gwt_version.setter
    def gwt_version(self, value):
        if self._gwt_version != UNKNOWN:
            return

        logger.info(f"Setting GWT version to {value}")
        self._gwt_version = value

    @property
    def rpc_version(self):
        if self._rpc_version != UNKNOWN:
            return

        return self._rpc_version

    @rpc_version.setter
    def rpc_version(self, value):
        logger.info(f"Setting RPC version to {value}")
        self._rpc_version = value

    @property
    def rpc_flags(self):
        return self._rpc_flags

    @rpc_flags.setter
    def rpc_flags(self, value):
        if self._rpc_flags != UNKNOWN:
            return

        logger.info(f"Setting RPC flags to {value}")
        self._rpc_flags = value

    @property
    def rpc_mode(self):
        return self._rpc_mode

    @rpc_mode.setter
    def rpc_mode(self, value):
        logger.info(f"Toggling RPC mode to {value}")
        self._rpc_mode = value

    @property
    def filter(self):
        return self._filter

    @filter.setter
    def filter(self, value):
        logger.info(f"Setting filter to {value}")
        self._filter = value
