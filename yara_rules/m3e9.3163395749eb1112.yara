import "hash"

rule m3e9_3163395749eb1112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163395749eb1112"
     cluster="m3e9.3163395749eb1112"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="otwycal wapomi vjadtre"
     md5_hashes="['9dbdcf4cccdca390d408037fd425b350', '2eb2e997ae3d3142243d36f73a11f6f4', '2eb2e997ae3d3142243d36f73a11f6f4']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

