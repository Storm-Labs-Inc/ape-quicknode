from ape import plugins

from .constants import QUICKNODE_NETWORKS
from .provider import QuickNode


@plugins.register(plugins.ProviderPlugin)
def providers():
    for ecosystem_name in QUICKNODE_NETWORKS:
        for network_name in QUICKNODE_NETWORKS[ecosystem_name]:
            yield ecosystem_name, network_name, QuickNode
