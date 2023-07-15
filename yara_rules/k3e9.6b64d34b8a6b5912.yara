import "hash"

rule k3e9_6b64d34b8a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b8a6b5912"
     cluster="k3e9.6b64d34b8a6b5912"
     cluster_size="496 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['bd276025bde8ef9ef60dbb69ad0184ad', 'a60421124390ca4a3a9fb0e67a83dec6', '128f2d417da97d57f019f10197418d95']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(8252,1036) == "bf35bc45826b9aa0cee18bd0fde1c00c"
}

