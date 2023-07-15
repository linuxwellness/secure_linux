import "hash"

rule k3e9_6b64d34e8a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34e8a4b5912"
     cluster="k3e9.6b64d34e8a4b5912"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['c1736a2db9d9281d11f539f3a36835b6', 'bcd06b2a114d8c996ce519b73a08748f', 'a75111f727de43f4f6e712826730231f']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(7216,1036) == "27a10cb18182bb90bc5569da36fb9e39"
}

