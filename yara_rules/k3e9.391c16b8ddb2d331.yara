import "hash"

rule k3e9_391c16b8ddb2d331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8ddb2d331"
     cluster="k3e9.391c16b8ddb2d331"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['e965488f8e2d25461c5f62320a45162d', '014242cdf63b196693daa7e3cfebadc3', 'ac3094022965110ee54e796e03b0d4b9']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1024) == "51c2f2679c0a685bf8eb5bfbed43035f"
}

