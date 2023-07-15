import "hash"

rule k3e9_6b64d36b8b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b8b4b5912"
     cluster="k3e9.6b64d36b8b4b5912"
     cluster_size="67 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['b554a9d7fce3286ac5c27ad52bf1d3ff', 'b142666ae8f2714f72685421aea038ac', '09f9e9cf9c04e5489a02b9c4a6555ba2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17576,1036) == "c9de54f1454eda93417385069e74c982"
}

