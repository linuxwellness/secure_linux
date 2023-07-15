
rule k2318_3713898ebe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713898ebe210b12"
     cluster="k2318.3713898ebe210b12"
     cluster_size="166"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['6cfbdcdf6ae0bf18bc7f9c058b2fb16a801f7682','a237a96c4655f4d08460b9ea1cea0e1606d6df8f','f4d14b737a91c994f4c6d68382542d69246516ee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713898ebe210b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
