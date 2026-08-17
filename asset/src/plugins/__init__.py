from src.plugins.base import AssetPlugin, AssetRecord, SyncResult

PLUGIN_REGISTRY: dict[str, type[AssetPlugin]] = {}

try:
    from src.plugins.ldap_ad import LdapAdAssetPlugin
    PLUGIN_REGISTRY["ldap_ad"] = LdapAdAssetPlugin
except ImportError:
    pass

try:
    from src.plugins.cloudtemple import CloudTempleAssetPlugin
    PLUGIN_REGISTRY["cloudtemple"] = CloudTempleAssetPlugin
except ImportError:
    pass

try:
    from src.plugins.aws import AwsAssetPlugin
    PLUGIN_REGISTRY["aws_ec2"] = AwsAssetPlugin
except ImportError:
    pass

try:
    from src.plugins.intune import IntuneAssetPlugin
    PLUGIN_REGISTRY["intune"] = IntuneAssetPlugin
except ImportError:
    pass

# Future plugins (scaffold — add when implemented):
# - defender     (Microsoft Defender for Endpoint)
# - crowdstrike  (CrowdStrike Falcon)
# - vsphere      (VMware vSphere / vCenter — direct, not via Cloud Temple)
# - azure        (Azure Resource Graph)
